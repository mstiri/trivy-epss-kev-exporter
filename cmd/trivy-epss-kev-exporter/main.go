// Command trivy-epss-kev-exporter is a read-only Prometheus exporter that
// enriches Trivy Operator VulnerabilityReport CVEs with EPSS scores and CISA KEV
// presence. See exporter/CLAUDE.md for the architecture and metric contract.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/prometheus/common/version"
	"golang.org/x/sync/errgroup"
	"k8s.io/klog/v2"

	"github.com/mstiri/trivy-epss-kev-exporter/internal/app"
	"github.com/mstiri/trivy-epss-kev-exporter/internal/controller"
	"github.com/mstiri/trivy-epss-kev-exporter/internal/server"
)

func main() {
	err := run()
	klog.Flush()
	if err != nil {
		klog.ErrorS(err, "exporter terminated")
		os.Exit(1)
	}
}

func run() error {
	fs := flag.NewFlagSet("trivy-epss-kev-exporter", flag.ContinueOnError)
	klog.InitFlags(fs)

	var (
		epssURL          = fs.String("epss-feed-url", envOr("EPSS_FEED_URL", app.DefaultEPSSURL), "EPSS bulk CSV feed URL (env EPSS_FEED_URL)")
		kevURL           = fs.String("kev-feed-url", envOr("KEV_FEED_URL", app.DefaultKEVURL), "CISA KEV JSON feed URL (env KEV_FEED_URL)")
		feedInterval     = fs.Duration("feed-refresh-interval", 24*time.Hour, "how often to refresh the feeds")
		feedTimeout      = fs.Duration("feed-http-timeout", 2*time.Minute, "per-fetch HTTP timeout for feeds")
		resyncInterval   = fs.Duration("resync-interval", 0, "informer resync interval (0 = disabled; not how feed changes are caught)")
		metricsPort      = fs.Int("metrics-port", 8080, "port for /metrics, /healthz, /readyz")
		metricsPath      = fs.String("metrics-path", "/metrics", "path to expose metrics on")
		logLevel         = fs.String("log-level", "info", "log level: info|debug|trace")
		namespaces       = fs.String("namespaces", envOr("NAMESPACES", ""), "comma-separated namespace allowlist (empty = all namespaces)")
		kubeconfig       = fs.String("kubeconfig", os.Getenv("KUBECONFIG"), "path to kubeconfig (empty = in-cluster, then default loading rules)")
		workers          = fs.Int("workers", 2, "number of concurrent reconcile workers")
		enableRollup     = fs.Bool("enable-rollup", true, "roll ReplicaSet workloads up to their owning Deployment (needs read RBAC on replicasets)")
		enableRansomware = fs.Bool("enable-ransomware", true, "emit the trivy_vuln_kev_ransomware gauge")
		userAgent        = fs.String("user-agent", "trivy-epss-kev-exporter", "User-Agent header for feed requests")
	)
	if err := fs.Parse(os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	applyLogLevel(fs, *logLevel)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	restCfg, err := controller.BuildConfig(*kubeconfig)
	if err != nil {
		return fmt.Errorf("kube config: %w", err)
	}
	clients, err := controller.NewClients(restCfg)
	if err != nil {
		return err
	}

	a, err := app.New(clients, app.Config{
		EPSSURL:             *epssURL,
		KEVURL:              *kevURL,
		FeedRefreshInterval: *feedInterval,
		FeedHTTPTimeout:     *feedTimeout,
		EnableRansomware:    *enableRansomware,
		Namespaces:          splitCSV(*namespaces),
		ResyncInterval:      *resyncInterval,
		Workers:             *workers,
		EnableRollup:        *enableRollup,
		UserAgent:           *userAgent,
	})
	if err != nil {
		return err
	}

	srv := server.New(a.Metrics().Registry(), a, server.Config{Port: *metricsPort, MetricsPath: *metricsPath})

	klog.InfoS("starting trivy-epss-kev-exporter",
		"version", version.Version, "revision", version.Revision, "goVersion", version.GoVersion,
		"epssURL", *epssURL, "kevURL", *kevURL,
		"rollup", *enableRollup, "ransomware", *enableRansomware,
		"namespaces", *namespaces, "metricsPort", *metricsPort)

	g, ctx := errgroup.WithContext(ctx)
	g.Go(func() error { return a.Run(ctx) })
	g.Go(func() error { return srv.Run(ctx) })

	if err := g.Wait(); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	klog.InfoS("shutdown complete")
	return nil
}

func applyLogLevel(fs *flag.FlagSet, level string) {
	v := "0"
	switch strings.ToLower(level) {
	case "debug":
		v = "3"
	case "trace":
		v = "5"
	}
	_ = fs.Set("v", v)
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
