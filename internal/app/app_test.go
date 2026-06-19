package app

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	kubefake "k8s.io/client-go/kubernetes/fake"

	"github.com/mstiri/trivy-epss-kev-exporter/internal/controller"
	"github.com/mstiri/trivy-epss-kev-exporter/internal/epss"
	"github.com/mstiri/trivy-epss-kev-exporter/internal/kev"
	"github.com/mstiri/trivy-epss-kev-exporter/internal/report"
)

var vrGVR = schema.GroupVersionResource{Group: "aquasecurity.github.io", Version: "v1alpha1", Resource: "vulnerabilityreports"}

func newTestApp(t *testing.T, cfg Config) *App {
	t.Helper()
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(),
		map[schema.GroupVersionResource]string{vrGVR: "VulnerabilityReportList"})
	kube := kubefake.NewSimpleClientset()
	a, err := New(&controller.Clients{Dynamic: dyn, Kube: kube}, cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return a
}

func countFamily(t *testing.T, a *App, name string) int {
	t.Helper()
	mfs, err := a.metrics.Registry().Gather()
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

func sampleReport() *report.VulnerabilityReport {
	return &report.VulnerabilityReport{
		Metadata: report.Metadata{
			Namespace: "litellm", Name: "rep1", UID: "u1",
			Labels: map[string]string{
				report.LabelResourceNamespace: "litellm",
				report.LabelResourceName:      "litellm-85bb58cf94",
				report.LabelResourceKind:      "ReplicaSet",
				report.LabelContainerName:     "litellm",
			},
		},
		Report: report.Spec{Vulnerabilities: []report.Vulnerability{
			{VulnerabilityID: "CVE-2021-44228", Resource: "log4j", Severity: "CRITICAL"},
		}},
	}
}

func TestReconcile_SetThenDelete(t *testing.T) {
	a := newTestApp(t, Config{EnableRansomware: true})
	a.snap.epss.Store(&epss.Snapshot{Scores: map[string]epss.Score{
		"CVE-2021-44228": {Score: 0.944, Percentile: 0.99999},
	}})
	kevSnap, err := kev.Parse(strings.NewReader(
		`{"catalogVersion":"v1","vulnerabilities":[{"cveID":"CVE-2021-44228","knownRansomwareCampaignUse":"Known"}]}`))
	if err != nil {
		t.Fatalf("kev.Parse: %v", err)
	}
	a.snap.kev.Store(kevSnap)

	rep := sampleReport()
	if err := a.reconcile("litellm/rep1", rep, rep.Workload(), true); err != nil {
		t.Fatalf("reconcile set: %v", err)
	}
	for _, name := range []string{"trivy_vuln_epss_score", "trivy_vuln_epss_percentile", "trivy_vuln_kev", "trivy_vuln_kev_ransomware"} {
		if c := countFamily(t, a, name); c != 1 {
			t.Errorf("%s series = %d, want 1", name, c)
		}
	}

	if err := a.reconcile("litellm/rep1", nil, report.Workload{}, false); err != nil {
		t.Fatalf("reconcile delete: %v", err)
	}
	if c := countFamily(t, a, "trivy_vuln_epss_score"); c != 0 {
		t.Errorf("after delete: %d series, want 0", c)
	}
}

func TestReady_GatesOnSyncAndBothFeeds(t *testing.T) {
	a := newTestApp(t, Config{})
	if a.Ready() {
		t.Error("must not be ready before sync/feeds")
	}
	a.onSynced(true)
	if a.Ready() {
		t.Error("must not be ready until feeds loaded")
	}
	a.snap.epssLoaded.Store(true)
	if a.Ready() {
		t.Error("must not be ready until BOTH feeds loaded")
	}
	a.snap.kevLoaded.Store(true)
	if !a.Ready() {
		t.Error("should be ready once synced and both feeds loaded")
	}
}

func TestLoadEPSS_FetchesParsesAndWiresApply(t *testing.T) {
	const feed = "#model_version:v2026.06.15,score_date:2026-06-16T12:03:06Z\n" +
		"cve,epss,percentile\nCVE-2021-44228,0.944,0.99999\n"
	var gotUA string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		_, _ = io.WriteString(w, feed)
	}))
	defer srv.Close()

	a := newTestApp(t, Config{EPSSURL: srv.URL, UserAgent: "test-ua"})
	res, err := a.loadEPSS(context.Background())
	if err != nil {
		t.Fatalf("loadEPSS: %v", err)
	}
	if res.Marker != [2]string{"v2026.06.15", "2026-06-16T12:03:06Z"} {
		t.Errorf("marker = %v", res.Marker)
	}
	if a.snap.epssLoaded.Load() {
		t.Error("must not be loaded before Apply")
	}
	res.Apply()
	if !a.snap.epssLoaded.Load() || a.snap.epss.Load() == nil {
		t.Error("Apply must store the snapshot and flag loaded")
	}
	if gotUA != "test-ua" {
		t.Errorf("User-Agent = %q, want test-ua", gotUA)
	}
}
