package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"

	"github.com/alecthomas/kong"
	"github.com/fsnotify/fsnotify"
	"github.com/prometheus/client_golang/prometheus"
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
	CertDir       string `required:"" help:"The certificate directory to watch for updates." env:"KVS_CERT_DIR"`
	ListenAddress string `name:"web.listen-address" default:":9533" help:"Address to listen on for web interface and telemetry."`
	MetricPath    string `name:"web.telemetry-path" default:"/metrics" help:"Path under which to expose metrics."`
	KvsHost       string `default:"127.0.0.1" help:"Host where the KeyValueStore is running." env:"KVS_HOST"`
	KvsPort       int    `default:"6379" help:"The port the KeyValueStore is listening on." env:"KVS_PORT"`
	KvsUser       string `default:"default" help:"User for the KeyValueStore." env:"KVS_USER"`
	KvsPassword   string `default:"" help:"Password for the KeyValueStore." env:"KVS_PASSWORD"`
	CertFilename  string `default:"tls.crt" help:"Filename of the tls cert." env:"KVS_CERT_FILENAME"`
	KeyFilename   string `default:"tls.key" help:"Filename of the tls key." env:"KVS_KEY_FILENAME"`
	CaFilename    string `default:"ca.crt" help:"Filename of the ca cert." env:"KVS_CA_FILENAME"`
}

var (
	lastReloadError = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "last_reload_error",
		Help:      "Whether the last reload resulted in an error (1 for error, 0 for success)",
	})
	successReloads = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "success_reloads_total",
		Help:      "Total successful reload calls",
	})
	reloadErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "reload_errors_total",
		Help:      "Total reload errors by reason",
	})
	watcherErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "watcher_errors_total",
		Help:      "Total filesystem watcher errors",
	})
	totalReloadRequests = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "requests_total",
		Help:      "Total reload requests",
	})
)

func init() {
	prometheus.MustRegister(lastReloadError)
	prometheus.MustRegister(successReloads)
	prometheus.MustRegister(reloadErrors)
	prometheus.MustRegister(watcherErrors)
	prometheus.MustRegister(totalReloadRequests)
}

func main() {
	ctx := context.Background()
	flags := &cli{}
	_ = kong.Parse(
		flags,
		kong.Name(scriptname),
		kong.Description("Reloads a KeyValueStore's TLS cert and key when they get replaced in the filesystem."),
		kong.UsageOnError(),
	)

	if err := validateCertificates(flags); err != nil {
		log.Fatalf("certificate validation failed: %v", err)
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}
	defer watcher.Close()

	kvsClient := newKvsClient(flags)
	defer kvsClient.Close()

	go func() {
		for {
			select {
			case event := <-watcher.Events:
				if !isValidEvent(event) {
					continue
				}
				log.Println("secret updated")

				log.Printf("performing KVS TLS reload on host %s", flags.KvsHost)
				log.Println("getting certificate path from config")

				path, err := getCertPath(ctx, kvsClient)
				if err != nil {
					setFailureMetrics()
					log.Println("error getting cert path: ", err)
					continue
				}

				log.Printf("certificate path is %s", path)

				err = reloadKvsCerts(ctx, flags, kvsClient, path)
				if err != nil {
					setFailureMetrics()
					log.Println("error triggering reload: ", err)
				} else {
					setSuccessMetrics()
					log.Println("successfully triggered reload")
				}

			case err := <-watcher.Errors:
				watcherErrors.Inc()
				log.Println("error:", err)
			}
		}
	}()

	log.Printf("watching directory: %q", flags.CertDir)
	err = watcher.Add(flags.CertDir)
	if err != nil {
		log.Fatal(err)
	}

	log.Fatal(serverMetrics(flags.ListenAddress, flags.MetricPath))
}

func newKvsClient(flags *cli) *redis.Client {
	return redis.NewClient(&redis.Options{
		Addr:      net.JoinHostPort(flags.KvsHost, strconv.Itoa(flags.KvsPort)),
		Username:  flags.KvsUser,
		Password:  flags.KvsPassword,
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

func reloadKvsCerts(ctx context.Context, flags *cli, client *redis.Client, path string) error {
	err := client.ConfigSet(ctx, caKey, filepath.Join(path, flags.CaFilename)).Err()
	if err != nil {
		return fmt.Errorf("error reloading tls ca file: %w", err)
	}

	err = client.ConfigSet(ctx, keyKey, filepath.Join(path, flags.KeyFilename)).Err()
	if err != nil {
		return fmt.Errorf("error reloading tls key file: %w", err)
	}

	err = client.ConfigSet(ctx, certKey, filepath.Join(path, flags.CertFilename)).Err()
	if err != nil {
		return fmt.Errorf("error reloading tls cert file: %w", err)
	}

	return nil
}

func setFailureMetrics() {
	totalReloadRequests.Inc()
	reloadErrors.Inc()
	lastReloadError.Set(1.0)
}

func setSuccessMetrics() {
	totalReloadRequests.Inc()
	successReloads.Inc()
	lastReloadError.Set(0.0)
}

func isValidEvent(event fsnotify.Event) bool {
	return event.Has(fsnotify.Write) || event.Has(fsnotify.Create)
}

func validateCertificates(flags *cli) error {
	dirInfo, err := os.Stat(flags.CertDir)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("certificate directory does not exist: %s", flags.CertDir)
		}
		return fmt.Errorf("error checking certificate directory: %w", err)
	}
	if !dirInfo.IsDir() {
		return fmt.Errorf("certificate path is not a directory: %s", flags.CertDir)
	}

	errs := []error{}
	for _, path := range []string{flags.CertFilename, flags.KeyFilename, flags.CaFilename} {
		filePath := filepath.Join(flags.CertDir, path)

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

func serverMetrics(ListenAddress, metricsPath string) error {
	http.Handle(metricsPath, promhttp.Handler())
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`
			<html>
			<head><title>KVS TLS Reloader Metrics</title></head>
			<body>
			<h1>KVS TLS Reloader</h1>
			<p><a href='` + metricsPath + `'>Metrics</a></p>
			</body>
			</html>
		`))
	})
	return http.ListenAndServe(ListenAddress, nil)
}
