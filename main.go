package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/alecthomas/kong"
	"github.com/fsnotify/fsnotify"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/redis/go-redis/v9"
	"github.com/redis/go-redis/v9/maintnotifications"
)

const (
	scriptname = "kvs-tls-reload"
	namespace  = "kvs_tls_reload"
	caKey      = "tls-ca-cert-file"
	certKey    = "tls-cert-file"
	keyKey     = "tls-key-file"
)

type cli struct {
	CertDir       string `required:"" help:"The certificate directory to watch for updates." type:"existingdir" env:"KVS_CERT_DIR"`
	ListenAddress string `name:"web.listen-address" default:":9533" help:"Address to listen on for web interface and telemetry."`
	MetricPath    string `name:"web.telemetry-path" default:"/metrics" help:"Path under which to expose metrics."`
	KvsHost       string `default:"127.0.0.1" help:"Host where the KeyValueStore is running." env:"KVS_HOST"`
	KvsPort       int    `default:"6379" help:"The port the KeyValueStore is listening on." env:"KVS_PORT"`
	KvsUser       string `default:"default" help:"User for the KeyValueStore." env:"KVS_USER"`
	KvsPassword   string `default:"" help:"Password for the KeyValueStore." env:"KVS_PASSWORD"`
	CertFilename  string `default:"tls.crt" help:"Filename of the tls cert." env:"KVS_CERT_FILENAME"`
	KeyFilename   string `default:"tls.key" help:"Filename of the tls key." env:"KVS_KEY_FILENAME"`
	CaFilename    string `default:"ca.crt" help:"Filename of the ca cert." env:"KVS_CA_FILENAME"`

	logger *slog.Logger
	client *redis.Client
}

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{}))
	if err := run(logger); err != nil {
		logger.Error(err.Error())
		os.Exit(1)
	}

	os.Exit(0)
}

func run(logger *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	c := &cli{
		logger: logger,
	}
	_ = kong.Parse(
		c,
		kong.Name(scriptname),
		kong.Description("Reloads a KeyValueStore's TLS cert and key when they get replaced in the filesystem."),
		kong.UsageOnError(),
	)

	if err := c.validateCertificates(); err != nil {
		return fmt.Errorf("certificate validation failed: %w", err)
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to create watcher: %w", err)
	}
	defer watcher.Close()

	c.client = c.newKvsClient()
	defer c.client.Close()

	const debounceDelay = 2 * time.Second
	var debounceTimer *time.Timer
	debounceMutex := sync.Mutex{}

	go func() {
		for {
			select {
			case event := <-watcher.Events:
				if !isValidEvent(event) {
					continue
				}
				c.logger.DebugContext(ctx, "secret update detected", "name", event.Name, "host", c.KvsHost)

				debounceMutex.Lock()
				if debounceTimer != nil {
					debounceTimer.Stop()
				}

				debounceTimer = time.AfterFunc(debounceDelay, func() {
					logger.InfoContext(ctx, "secret update detected, reloading tls configuration", "delay", debounceDelay.String())
					c.handleEvent(ctx, event)
				})
				debounceMutex.Unlock()

			case err := <-watcher.Errors:
				watcherErrors.Inc()
				if err != nil {
					logger.ErrorContext(ctx, "error watching directory", "error", err)
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	logger.InfoContext(ctx, "watching directory", "path", c.CertDir)
	if err := watcher.Add(c.CertDir); err != nil {
		return fmt.Errorf("failed to add directory to watcher: %w", err)
	}

	return c.serveMetrics(ctx)
}

func (c *cli) handleEvent(ctx context.Context, event fsnotify.Event) {
	path, err := getCertPath(ctx, c.client)
	if err != nil {
		c.logger.ErrorContext(ctx, "error getting cert path", "error", err)

		setFailureMetrics()
		return
	}

	if err := c.reloadTLSConfig(ctx, path); err != nil {
		c.logger.ErrorContext(ctx, "error triggering reload", "error", err, "path", path)

		setFailureMetrics()
		return
	}

	setSuccessMetrics()
}

func (c *cli) newKvsClient() *redis.Client {
	return redis.NewClient(&redis.Options{
		Addr:      net.JoinHostPort(c.KvsHost, strconv.Itoa(c.KvsPort)),
		Username:  c.KvsUser,
		Password:  c.KvsPassword,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true},
		MaintNotificationsConfig: &maintnotifications.Config{
			Mode: maintnotifications.ModeDisabled,
		},
	})
}

func getCertPath(ctx context.Context, client *redis.Client) (string, error) {
	res, err := client.ConfigGet(ctx, certKey).Result()
	if err != nil {
		return "", fmt.Errorf("error getting tls cert file: %w", err)
	}

	certFile, exists := res[certKey]
	if !exists {
		return "", fmt.Errorf("no tls cert configured")
	}

	return filepath.Dir(certFile), nil
}

func (c *cli) reloadTLSConfig(ctx context.Context, path string) error {
	ca := filepath.Join(path, c.CaFilename)
	key := filepath.Join(path, c.KeyFilename)
	cert := filepath.Join(path, c.CertFilename)

	if err := c.client.Do(ctx, "config", "set",
		caKey, ca,
		keyKey, key,
		certKey, cert,
	).Err(); err != nil {
		return fmt.Errorf("error reloading tls configuration: %w", err)
	}

	c.logger.InfoContext(ctx, "successfully triggered reload", "ca", ca, "key", key, "cert", cert)

	return nil
}

func isValidEvent(event fsnotify.Event) bool {
	return event.Has(fsnotify.Write) || event.Has(fsnotify.Create)
}

func (c *cli) validateCertificates() error {
	errs := []error{}
	for _, path := range []string{c.CertFilename, c.KeyFilename, c.CaFilename} {
		filePath := filepath.Join(c.CertDir, path)

		if _, err := os.Stat(filePath); err != nil {
			if os.IsNotExist(err) {
				errs = append(errs, fmt.Errorf("%s file does not exist: %s", path, filePath))
			} else {
				errs = append(errs, fmt.Errorf("error checking %s file: %w", path, err))
			}
		}
	}

	return errors.Join(errs...)
}

func (c *cli) serveMetrics(ctx context.Context) error {
	ln, err := net.Listen("tcp", c.ListenAddress)
	if err != nil {
		return fmt.Errorf("error listening on %s: %w", c.ListenAddress, err)
	}
	c.logger.InfoContext(ctx, "listening", "addr", c.ListenAddress)

	h := http.NewServeMux()
	h.Handle(c.MetricPath, promhttp.Handler())
	h.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`
			<html>
			<head><title>KVS TLS Reloader Metrics</title></head>
			<body>
			<h1>KVS TLS Reloader</h1>
			<p><a href='` + c.MetricPath + `'>Metrics</a></p>
			</body>
			</html>
		`))
	})

	server := &http.Server{
		BaseContext:       func(l net.Listener) context.Context { return ctx },
		ReadHeaderTimeout: 10 * time.Second,
		Handler:           h,
		ErrorLog:          slog.NewLogLogger(c.logger.Handler(), slog.LevelError),
	}
	defer server.Close()

	go func() {
		if err := server.Serve(ln); err != nil && err != http.ErrServerClosed {
			c.logger.ErrorContext(ctx, "error serving metrics", "error", err)
		}
	}()
	<-ctx.Done()

	c.logger.InfoContext(ctx, "shutting down server", "addr", c.ListenAddress)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	return server.Shutdown(ctx)
}
