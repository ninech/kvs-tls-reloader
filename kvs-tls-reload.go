package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"

	fsnotify "github.com/fsnotify/fsnotify"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/redis/go-redis/v9"
)

const namespace = "kvs_tls_reload"

var (
	volumeDir     = flag.String("volume-dir", "", "The secret volume directory to watch for updates.")
	listenAddress = flag.String("web.listen-address", ":9533", "Address to listen on for web interface and telemetry.")
	metricPath    = flag.String("web.telemetry-path", "/metrics", "Path under which to expose metrics.")
	kvsHost       = flag.String("kvs-host", "127.0.0.1", "Host where the KeyValueStore is running.")
	kvsPort       = flag.Int("kvs-port", 6379, "The port the KeyValueStore is listening on.")
	kvsTLSEnabled = flag.Bool("kvs-tls", true, "Connect to the KeyValueStore using TLS.")
	kvsUser       = flag.String("kvs-user", "default", "User for the KeyValueStore.")
	kvsPassword   = flag.String("kvs-password", "", "Password for the KeyValueStore.")

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
	flag.Parse()
	ctx := context.Background()

	if *volumeDir == "" {
		log.Println("Missing volume-dir")
		log.Println()
		flag.Usage()
		os.Exit(1)
	}

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

				kvsClient := newKvsClient()

				log.Printf("performing KVS TLS reload on volume path %s", *volumeDir)

				err := reloadKvsCerts(ctx, kvsClient)
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

	log.Printf("Watching directory: %q", *volumeDir)
	err = watcher.Add(*volumeDir)
	if err != nil {
		log.Fatal(err)
	}

	log.Fatal(serverMetrics(*listenAddress, *metricPath))
}

func newKvsClient() *redis.Client {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}
	if !*kvsTLSEnabled {
		tlsConfig = nil
	}

	return redis.NewClient(&redis.Options{
		Addr:      net.JoinHostPort(*kvsHost, strconv.Itoa(*kvsPort)),
		Username:  *kvsUser,
		Password:  *kvsPassword,
		TLSConfig: tlsConfig,
	})
}

func reloadKvsCerts(ctx context.Context, client *redis.Client) error {
	err := client.ConfigSet(ctx, "tls-ca-cert-file", *volumeDir+"ca.crt").Err()
	if err != nil {
		return fmt.Errorf("error reloading tls key file: %w", err)
	}

	err = client.ConfigSet(ctx, "tls-key-file", *volumeDir+"tls.key").Err()
	if err != nil {
		return fmt.Errorf("error reloading tls key file: %w", err)
	}

	err = client.ConfigSet(ctx, "tls-cert-file", *volumeDir+"tls.crt").Err()
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
	if event.Op&fsnotify.Create != fsnotify.Create {
		return false
	}
	if filepath.Base(event.Name) != "..data" {
		return false
	}
	return true
}

func serverMetrics(listenAddress, metricsPath string) error {
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
	return http.ListenAndServe(listenAddress, nil)
}
