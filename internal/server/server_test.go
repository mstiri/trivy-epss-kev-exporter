package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mstiri/trivy-epss-kev-exporter/internal/metrics"
)

type stubReady struct{ ready bool }

func (s *stubReady) Ready() bool { return s.ready }

func newServer(ready bool) *Server {
	m := metrics.New(metrics.Options{})
	m.SetCacheSynced(true) // ensure at least one exporter metric is present
	return New(m.Registry(), &stubReady{ready: ready}, Config{})
}

func do(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

func TestHealthz_AlwaysOK(t *testing.T) {
	// Even when not ready, liveness is OK.
	rec := do(t, newServer(false).Handler(), "/healthz")
	if rec.Code != http.StatusOK {
		t.Errorf("/healthz = %d, want 200", rec.Code)
	}
}

func TestReadyz_GatedOnReadiness(t *testing.T) {
	if rec := do(t, newServer(false).Handler(), "/readyz"); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("/readyz (not ready) = %d, want 503", rec.Code)
	}
	if rec := do(t, newServer(true).Handler(), "/readyz"); rec.Code != http.StatusOK {
		t.Errorf("/readyz (ready) = %d, want 200", rec.Code)
	}
}

func TestMetrics_ServesRegistry(t *testing.T) {
	rec := do(t, newServer(true).Handler(), "/metrics")
	if rec.Code != http.StatusOK {
		t.Fatalf("/metrics = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "trivy_exporter_cache_synced") {
		t.Errorf("/metrics body missing expected metric; got:\n%s", rec.Body.String())
	}
}

func TestMetrics_CustomPath(t *testing.T) {
	m := metrics.New(metrics.Options{})
	s := New(m.Registry(), &stubReady{ready: true}, Config{MetricsPath: "/custom-metrics"})
	if rec := do(t, s.Handler(), "/custom-metrics"); rec.Code != http.StatusOK {
		t.Errorf("/custom-metrics = %d, want 200", rec.Code)
	}
	if rec := do(t, s.Handler(), "/metrics"); rec.Code != http.StatusNotFound {
		t.Errorf("/metrics (not configured) = %d, want 404", rec.Code)
	}
}
