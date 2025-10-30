package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"

	"github.com/alecthomas/kong"
	fsnotify "github.com/fsnotify/fsnotify"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/redis/go-redis/v9"
)

const (
	scriptname = "kvs-tls-reload"
	namespace  = "kvs_tls_reload"
)

type cli struct {
	VolumeDir     string `required:"" help:"The secret volume directory to watch for updates." env:"VOLUME_DIR"`
	ListenAddress string `name:"web.listen-address" default:":9533" help:"Address to listen on for web interface and telemetry."`
	MetricPath    string `name:"web.telemetry-path" default:"/metrics" help:"Path under which to expose metrics."`
	KvsHost       string `default:"127.0.0.1" help:"Host where the KeyValueStore is running."`
	KvsPort       int    `default:"6379" help:"The port the KeyValueStore is listening on."`
	KvsTLSEnabled bool   `default:"true" help:"Connect to the KeyValueStore using TLS."`
	KvsUser       string `default:"default" help:"User for the KeyValueStore." env:"KVS_USER"`
	KvsPassword   string `default:"" help:"Password for the KeyValueStore." env:"KVS_PASSWORD"`
	CertFilename  string `default:"tls.crt" help:"Filename of the tls cert."`
	KeyFilename   string `default:"tls.key" help:"Filename of the tls key."`
	CaFilename    string `default:"ca.crt" help:"Filename of the ca cert."`
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
	reloadErrorsByReason = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "reload_errors_total",
		Help:      "Total reload errors by reason",
	}, []string{"reason"})
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
	prometheus.MustRegister(reloadErrorsByReason)
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

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}
	defer watcher.Close()

	go func() {
		for {
			select {
			case event := <-watcher.Events:
				if !isValidEvent(event) {
					continue
				}
				log.Println("secret updated")

				kvsClient := newKvsClient(flags)

				log.Printf("performing KVS TLS reload on volume path %s", flags.VolumeDir)

				err := reloadKvsCerts(ctx, flags, kvsClient)
				if err != nil {
					setFailureMetrics(err.Error())
					log.Println("error triggering reload")
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

	log.Printf("Watching directory: %q", flags.VolumeDir)
	err = watcher.Add(flags.VolumeDir)
	if err != nil {
		log.Fatal(err)
	}

	log.Fatal(serverMetrics(flags.ListenAddress, flags.MetricPath))
}

func newKvsClient(flags *cli) *redis.Client {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}
	if !flags.KvsTLSEnabled {
		tlsConfig = nil
	}

	return redis.NewClient(&redis.Options{
		Addr:      net.JoinHostPort(flags.KvsHost, strconv.Itoa(flags.KvsPort)),
		Username:  flags.KvsUser,
		Password:  flags.KvsPassword,
		TLSConfig: tlsConfig,
	})
}

func reloadKvsCerts(ctx context.Context, flags *cli, client *redis.Client) error {
	err := client.ConfigSet(ctx, "tls-ca-cert-file", flags.VolumeDir+flags.CaFilename).Err()
	if err != nil {
		return fmt.Errorf("error reloading tls key file: %w", err)
	}

	err = client.ConfigSet(ctx, "tls-key-file", flags.VolumeDir+flags.KeyFilename).Err()
	if err != nil {
		return fmt.Errorf("error reloading tls key file: %w", err)
	}

	err = client.ConfigSet(ctx, "tls-cert-file", flags.VolumeDir+flags.CertFilename).Err()
	if err != nil {
		return fmt.Errorf("error reloading tls cert file: %w", err)
	}

	return nil
}

func setFailureMetrics(reason string) {
	totalReloadRequests.Inc()
	reloadErrorsByReason.WithLabelValues(reason).Inc()
	lastReloadError.Set(1.0)
}

func setSuccessMetrics() {
	totalReloadRequests.Inc()
	successReloads.Inc()
	lastReloadError.Set(0.0)
}

func isValidEvent(event fsnotify.Event) bool {
	if !event.Has(fsnotify.Op(fsnotify.Write)) {
		return false
	}
	return true
}

func serverMetrics(ListenAddress, metricsPath string) error {
	http.Handle(metricsPath, promhttp.Handler())
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`
			<html>
			<head><title>KVS TLS Reload Metrics</title></head>
			<body>
			<h1>KVS TLS Reload</h1>
			<p><a href='` + metricsPath + `'>Metrics</a></p>
			</body>
			</html>
		`))
	})
	return http.ListenAndServe(ListenAddress, nil)
}
