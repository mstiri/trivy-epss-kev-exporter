// Package server exposes the exporter's HTTP surface: /metrics (Prometheus),
// /healthz (liveness), and /readyz (readiness). It is deliberately decoupled
// from app — it takes a metrics Gatherer and a Readiness probe, nothing more.
package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"k8s.io/klog/v2"
)

// Readiness reports whether the exporter is ready to serve meaningful metrics
// (informer cache synced AND both feeds loaded at least once).
type Readiness interface {
	Ready() bool
}

// Config configures the HTTP server.
type Config struct {
	Port        int
	MetricsPath string
}

func (c Config) withDefaults() Config {
	if c.Port == 0 {
		c.Port = 8080
	}
	if c.MetricsPath == "" {
		c.MetricsPath = "/metrics"
	}
	return c
}

// Server serves the metrics and probe endpoints.
type Server struct {
	gatherer prometheus.Gatherer
	ready    Readiness
	cfg      Config
}

// New builds the server. gatherer is the metrics registry; ready gates /readyz.
func New(gatherer prometheus.Gatherer, ready Readiness, cfg Config) *Server {
	return &Server{gatherer: gatherer, ready: ready, cfg: cfg.withDefaults()}
}

// Handler builds the HTTP mux. Exposed so it can be exercised in tests without
// binding a socket.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle(s.cfg.MetricsPath, promhttp.HandlerFor(s.gatherer, promhttp.HandlerOpts{}))

	// Liveness: the process is up and the HTTP server is responsive. It does NOT
	// depend on feeds or the informer — a not-ready exporter is still alive and
	// must not be restart-looped.
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok")
	})

	// Readiness: gated on informer sync AND both feeds loaded once.
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		if s.ready.Ready() {
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "ready")
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, "not ready")
	})

	return mux
}

// Run serves until ctx is cancelled, then shuts down gracefully.
func (s *Server) Run(ctx context.Context) error {
	srv := &http.Server{
		Addr:              fmt.Sprintf(":%d", s.cfg.Port),
		Handler:           s.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			klog.ErrorS(err, "http server graceful shutdown failed")
		}
	}()

	klog.InfoS("serving http", "addr", srv.Addr, "metricsPath", s.cfg.MetricsPath)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("server: %w", err)
	}
	return nil
}
