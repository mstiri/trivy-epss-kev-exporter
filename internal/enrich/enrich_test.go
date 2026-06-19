package enrich

import (
	"os"
	"strings"
	"testing"

	"github.com/mstiri/trivy-epss-kev-exporter/internal/epss"
	"github.com/mstiri/trivy-epss-kev-exporter/internal/kev"
	"github.com/mstiri/trivy-epss-kev-exporter/internal/report"
)

func operatorReport(vulns ...report.Vulnerability) *report.VulnerabilityReport {
	return &report.VulnerabilityReport{
		Metadata: report.Metadata{
			Namespace: "litellm",
			UID:       "uid-1",
			Labels: map[string]string{
				report.LabelResourceNamespace: "litellm",
				report.LabelResourceName:      "litellm-85bb58cf94",
				report.LabelResourceKind:      "ReplicaSet",
				report.LabelContainerName:     "litellm",
			},
		},
		Report: report.Spec{Vulnerabilities: vulns},
	}
}

func TestReport_Enrichment(t *testing.T) {
	rep := operatorReport(
		report.Vulnerability{VulnerabilityID: "CVE-2021-44228", Resource: "log4j", Severity: "CRITICAL"},
		report.Vulnerability{VulnerabilityID: "CVE-2021-44228", Resource: "log4j", Severity: "CRITICAL"}, // exact dup
		report.Vulnerability{VulnerabilityID: "CVE-2023-39810", Resource: "busybox", Severity: "HIGH"},   // EPSS only
		report.Vulnerability{VulnerabilityID: "CVE-9999-0000", Resource: "foo", Severity: ""},            // neither feed; empty severity
	)
	epssSnap := &epss.Snapshot{Scores: map[string]epss.Score{
		"CVE-2021-44228": {Score: 0.944, Percentile: 0.99999},
		"CVE-2023-39810": {Score: 0.1, Percentile: 0.5},
	}}
	kevSnap, err := kev.Parse(strings.NewReader(
		`{"catalogVersion":"v1","vulnerabilities":[{"cveID":"CVE-2021-44228","knownRansomwareCampaignUse":"Known"}]}`))
	if err != nil {
		t.Fatalf("kev.Parse: %v", err)
	}

	series := Report(rep, rep.Workload(), epssSnap, kevSnap)
	if len(series) != 3 {
		t.Fatalf("got %d series, want 3 (exact duplicate must collapse)", len(series))
	}

	by := map[string]Series{}
	for _, s := range series {
		by[s.Labels.CVE] = s
	}

	// log4j: in EPSS + KEV + ransomware, workload resolved from operator labels.
	got := by["CVE-2021-44228"]
	wantLabels := Labels{
		CVE: "CVE-2021-44228", Namespace: "litellm", Workload: "litellm-85bb58cf94",
		WorkloadKind: "ReplicaSet", Container: "litellm", Resource: "log4j", Severity: "CRITICAL",
	}
	if got.Labels != wantLabels {
		t.Errorf("labels = %+v, want %+v", got.Labels, wantLabels)
	}
	if got.EPSSScore != 0.944 || got.EPSSPercentile != 0.99999 || got.KEV != 1 || got.KEVRansomware != 1 {
		t.Errorf("44228 values = %+v, want epss 0.944/0.99999 kev 1 ransomware 1", got)
	}

	// busybox: EPSS only — KEV and ransomware must be 0.
	got = by["CVE-2023-39810"]
	if got.EPSSScore != 0.1 || got.KEV != 0 || got.KEVRansomware != 0 {
		t.Errorf("39810 values = %+v, want epss 0.1 kev 0 ransomware 0", got)
	}

	// Unscored, not in KEV: EPSS emits 0 (not omitted), severity defaults to UNKNOWN.
	got = by["CVE-9999-0000"]
	if got.EPSSScore != 0 || got.EPSSPercentile != 0 || got.KEV != 0 {
		t.Errorf("absent CVE values = %+v, want all zero", got)
	}
	if got.Labels.Severity != "UNKNOWN" {
		t.Errorf("empty severity = %q, want UNKNOWN", got.Labels.Severity)
	}
}

func TestReport_NilSnapshotsEnrichToZero(t *testing.T) {
	rep := operatorReport(report.Vulnerability{VulnerabilityID: "CVE-2021-44228", Resource: "log4j", Severity: "HIGH"})
	series := Report(rep, rep.Workload(), nil, nil)
	if len(series) != 1 {
		t.Fatalf("got %d series, want 1", len(series))
	}
	s := series[0]
	if s.EPSSScore != 0 || s.EPSSPercentile != 0 || s.KEV != 0 || s.KEVRansomware != 0 {
		t.Errorf("nil snapshots should enrich to zero, got %+v", s)
	}
}

func TestReport_NilReport(t *testing.T) {
	if got := Report(nil, report.Workload{}, nil, nil); got != nil {
		t.Errorf("Report(nil) = %v, want nil", got)
	}
}

func TestLabels_ValuesMatchLabelNames(t *testing.T) {
	l := Labels{"CVE-1", "ns", "wl", "Deployment", "c", "pkg", "HIGH"}
	vals := l.Values()
	if len(vals) != len(LabelNames) {
		t.Fatalf("Values len %d != LabelNames len %d", len(vals), len(LabelNames))
	}
	want := []string{"CVE-1", "ns", "wl", "Deployment", "c", "pkg", "HIGH"}
	for i := range vals {
		if vals[i] != want[i] {
			t.Errorf("Values()[%d] (%s) = %q, want %q", i, LabelNames[i], vals[i], want[i])
		}
	}
}

// TestReport_RealSample validates de-dup and workload resolution against the
// real CRD sample from CLAUDE.md (13 vuln entries, 3 of them exact duplicates).
func TestReport_RealSample(t *testing.T) {
	data, err := os.ReadFile("testdata/sample-report.json")
	if err != nil {
		t.Skipf("sample fixture not available: %v", err)
	}
	rep, err := report.FromJSON(data)
	if err != nil {
		t.Fatalf("FromJSON: %v", err)
	}

	// nil snapshots: we are asserting structure (de-dup, labels), not feed values.
	series := Report(rep, rep.Workload(), nil, nil)
	if len(series) != 10 {
		t.Fatalf("got %d series, want 10 (13 entries minus 3 duplicates)", len(series))
	}

	counts := map[string]int{}
	for _, s := range series {
		counts[s.Labels.CVE]++
		// Every series shares the same resolved workload, from operator labels.
		if s.Labels.Namespace != "litellm" || s.Labels.Workload != "litellm-85bb58cf94" ||
			s.Labels.WorkloadKind != "ReplicaSet" || s.Labels.Container != "litellm" {
			t.Errorf("workload mis-resolved for %s: %+v", s.Labels.CVE, s.Labels)
		}
	}
	// The three CVEs duplicated in the source must each appear exactly once.
	for _, cve := range []string{"CVE-2026-42561", "CVE-2026-44431", "CVE-2026-44432"} {
		if counts[cve] != 1 {
			t.Errorf("duplicated CVE %s appears %d times, want 1", cve, counts[cve])
		}
	}
}
