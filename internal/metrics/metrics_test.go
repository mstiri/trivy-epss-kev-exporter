package metrics

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"

	"github.com/mstiri/trivy-epss-kev-exporter/internal/enrich"
)

func lbl(cve, resource string) enrich.Labels {
	return enrich.Labels{
		CVE: cve, Namespace: "ns", Workload: "w", WorkloadKind: "Deployment",
		Container: "c", Resource: resource, Severity: "HIGH",
	}
}

func series(l enrich.Labels, epss, pct, kev, rans float64) enrich.Series {
	return enrich.Series{Labels: l, EPSSScore: epss, EPSSPercentile: pct, KEV: kev, KEVRansomware: rans}
}

func wantLabels(l enrich.Labels) map[string]string {
	out := make(map[string]string, len(enrich.LabelNames))
	vals := l.Values()
	for i, n := range enrich.LabelNames {
		out[n] = vals[i]
	}
	return out
}

func countSeries(t *testing.T, reg *prometheus.Registry, name string) int {
	t.Helper()
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() == name {
			return len(mf.GetMetric())
		}
	}
	return 0
}

func familyExists(t *testing.T, reg *prometheus.Registry, name string) bool {
	t.Helper()
	mfs, _ := reg.Gather()
	for _, mf := range mfs {
		if mf.GetName() == name {
			return true
		}
	}
	return false
}

func findValue(t *testing.T, reg *prometheus.Registry, name string, want map[string]string) (float64, bool) {
	t.Helper()
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		for _, m := range mf.GetMetric() {
			if labelsMatch(m.GetLabel(), want) {
				if g := m.GetGauge(); g != nil {
					return g.GetValue(), true
				}
				if c := m.GetCounter(); c != nil {
					return c.GetValue(), true
				}
			}
		}
	}
	return 0, false
}

func labelsMatch(got []*dto.LabelPair, want map[string]string) bool {
	if len(got) != len(want) {
		return false
	}
	for _, lp := range got {
		if want[lp.GetName()] != lp.GetValue() {
			return false
		}
	}
	return true
}

func TestSetReport_EmitsAllGauges(t *testing.T) {
	m := New(Options{EnableRansomware: true})
	l := lbl("CVE-1", "pkg")
	m.SetReport("uid1", []enrich.Series{series(l, 0.5, 0.9, 1, 1)})

	want := wantLabels(l)
	for _, tc := range []struct {
		name string
		want float64
	}{
		{"trivy_vuln_epss_score", 0.5},
		{"trivy_vuln_epss_percentile", 0.9},
		{"trivy_vuln_kev", 1},
		{"trivy_vuln_kev_ransomware", 1},
	} {
		got, ok := findValue(t, m.reg, tc.name, want)
		if !ok {
			t.Errorf("%s: series not found", tc.name)
		} else if got != tc.want {
			t.Errorf("%s = %v, want %v", tc.name, got, tc.want)
		}
	}

	if v := testutil.ToFloat64(m.reportsProcessed); v != 1 {
		t.Errorf("reports_processed = %v, want 1", v)
	}
	if v := testutil.ToFloat64(m.cvesEnriched); v != 1 {
		t.Errorf("cves_enriched = %v, want 1", v)
	}
}

func TestSetReport_ReplaceDropsStaleSeries(t *testing.T) {
	m := New(Options{})
	a, b := lbl("CVE-A", "pkgA"), lbl("CVE-B", "pkgB")
	m.SetReport("uid1", []enrich.Series{series(a, 0.1, 0, 0, 0), series(b, 0.2, 0, 0, 0)})
	if c := countSeries(t, m.reg, "trivy_vuln_epss_score"); c != 2 {
		t.Fatalf("after add: %d series, want 2", c)
	}

	// Re-enrich with only A (B's vuln got fixed) — B's series must be removed.
	m.SetReport("uid1", []enrich.Series{series(a, 0.1, 0, 0, 0)})
	if c := countSeries(t, m.reg, "trivy_vuln_epss_score"); c != 1 {
		t.Fatalf("after shrink: %d series, want 1", c)
	}
	if _, ok := findValue(t, m.reg, "trivy_vuln_epss_score", wantLabels(b)); ok {
		t.Error("stale series for CVE-B should be deleted")
	}
	if _, ok := findValue(t, m.reg, "trivy_vuln_epss_score", wantLabels(a)); !ok {
		t.Error("CVE-A series should remain")
	}
}

func TestSetReport_UpdatesValueOnReenrich(t *testing.T) {
	m := New(Options{})
	l := lbl("CVE-1", "pkg")
	m.SetReport("uid1", []enrich.Series{series(l, 0.10, 0, 0, 0)})
	// Feed changed: EPSS recomputed higher.
	m.SetReport("uid1", []enrich.Series{series(l, 0.80, 0, 0, 0)})
	if v, _ := findValue(t, m.reg, "trivy_vuln_epss_score", wantLabels(l)); v != 0.80 {
		t.Errorf("epss_score = %v, want updated 0.80", v)
	}
	if c := countSeries(t, m.reg, "trivy_vuln_epss_score"); c != 1 {
		t.Errorf("re-enrich must not duplicate: %d series, want 1", c)
	}
}

func TestDeleteReport_RemovesAll(t *testing.T) {
	m := New(Options{})
	a, b := lbl("CVE-A", "pkgA"), lbl("CVE-B", "pkgB")
	m.SetReport("uid1", []enrich.Series{series(a, 0.1, 0, 0, 0), series(b, 0.2, 0, 0, 0)})
	m.DeleteReport("uid1")
	if c := countSeries(t, m.reg, "trivy_vuln_epss_score"); c != 0 {
		t.Errorf("after delete: %d series, want 0", c)
	}
}

// TestRefcount_SharedTupleAcrossReports is the step-5 roll-up case: two reports
// (old + new ReplicaSet during a rollout) both own the same label-tuple. The
// gauge must survive deletion of one report and disappear only when both go.
func TestRefcount_SharedTupleAcrossReports(t *testing.T) {
	m := New(Options{})
	shared := lbl("CVE-SHARED", "pkg")
	m.SetReport("uidOld", []enrich.Series{series(shared, 0.5, 0, 1, 0)})
	m.SetReport("uidNew", []enrich.Series{series(shared, 0.5, 0, 1, 0)})

	if c := countSeries(t, m.reg, "trivy_vuln_epss_score"); c != 1 {
		t.Fatalf("shared tuple should collapse to 1 series, got %d", c)
	}

	m.DeleteReport("uidOld")
	if _, ok := findValue(t, m.reg, "trivy_vuln_epss_score", wantLabels(shared)); !ok {
		t.Error("series dropped too early: uidNew still references it")
	}

	m.DeleteReport("uidNew")
	if c := countSeries(t, m.reg, "trivy_vuln_epss_score"); c != 0 {
		t.Errorf("series should be gone after last owner deleted, got %d", c)
	}
}

func TestRansomware_DisabledNotRegistered(t *testing.T) {
	m := New(Options{EnableRansomware: false})
	if m.kevRansomware != nil {
		t.Fatal("kevRansomware vec should be nil when disabled")
	}
	// Must not panic even though Series carries a ransomware value.
	m.SetReport("uid1", []enrich.Series{series(lbl("CVE-1", "pkg"), 0.1, 0, 1, 1)})
	if familyExists(t, m.reg, "trivy_vuln_kev_ransomware") {
		t.Error("trivy_vuln_kev_ransomware must not be exposed when disabled")
	}
	// But kev itself is still there.
	if c := countSeries(t, m.reg, "trivy_vuln_kev"); c != 1 {
		t.Errorf("trivy_vuln_kev series = %d, want 1", c)
	}
}

func TestSelfMetrics(t *testing.T) {
	m := New(Options{})

	m.FeedRefreshSucceeded("epss", time.Unix(1000, 0))
	if v, ok := findValue(t, m.reg, "trivy_exporter_feed_last_success_timestamp_seconds", map[string]string{"feed": "epss"}); !ok || v != 1000 {
		t.Errorf("feed_last_success epss = %v ok=%v, want 1000", v, ok)
	}

	m.FeedRefreshFailed("kev")
	m.FeedRefreshFailed("kev")
	if v, _ := findValue(t, m.reg, "trivy_exporter_feed_refresh_failures_total", map[string]string{"feed": "kev"}); v != 2 {
		t.Errorf("feed_refresh_failures kev = %v, want 2", v)
	}

	m.SetCacheSynced(true)
	if v := testutil.ToFloat64(m.cacheSynced); v != 1 {
		t.Errorf("cache_synced = %v, want 1", v)
	}
	m.SetCacheSynced(false)
	if v := testutil.ToFloat64(m.cacheSynced); v != 0 {
		t.Errorf("cache_synced = %v, want 0", v)
	}
}

// The registry must expose without duplicate-registration or collision errors.
func TestRegistryGathers(t *testing.T) {
	m := New(Options{EnableRansomware: true})
	if _, err := m.reg.Gather(); err != nil {
		t.Fatalf("registry Gather failed: %v", err)
	}
}

func TestBuildInfoRegistered(t *testing.T) {
	m := New(Options{})
	if !familyExists(t, m.reg, "trivy_exporter_build_info") {
		t.Error("trivy_exporter_build_info not exposed")
	}
}
