package kev

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

const sampleFeed = `{
  "title": "CISA Catalog of Known Exploited Vulnerabilities",
  "catalogVersion": "2026.06.15",
  "dateReleased": "2026-06-15T19:00:14.5797Z",
  "count": 3,
  "vulnerabilities": [
    {"cveID": "CVE-2021-44228", "knownRansomwareCampaignUse": "Known"},
    {"cveID": "CVE-2026-54420", "knownRansomwareCampaignUse": "Unknown"},
    {"cveID": "CVE-2024-3400",  "knownRansomwareCampaignUse": ""}
  ]
}`

func TestParse_HappyPath(t *testing.T) {
	snap, err := Parse(strings.NewReader(sampleFeed))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got, want := snap.Len(), 3; got != want {
		t.Errorf("Len = %d, want %d", got, want)
	}
	if cv, dr := snap.Marker(); cv != "2026.06.15" || dr != "2026-06-15T19:00:14.5797Z" {
		t.Errorf("Marker = %q/%q, want 2026.06.15/2026-06-15T19:00:14.5797Z", cv, dr)
	}

	if !snap.Has("CVE-2021-44228") {
		t.Error("CVE-2021-44228 should be present")
	}
	if snap.Has("CVE-0000-0000") {
		t.Error("absent CVE should not be present")
	}
}

func TestRansomware(t *testing.T) {
	snap, err := Parse(strings.NewReader(sampleFeed))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !snap.IsRansomware("CVE-2021-44228") {
		t.Error("CVE-2021-44228 is flagged Known → ransomware true")
	}
	if snap.IsRansomware("CVE-2026-54420") {
		t.Error("Unknown must not be flagged ransomware")
	}
	if snap.IsRansomware("CVE-2024-3400") {
		t.Error("empty ransomware field must not be flagged")
	}
	// A CVE not in the catalog is never ransomware.
	if snap.IsRansomware("CVE-0000-0000") {
		t.Error("absent CVE must not be flagged ransomware")
	}
}

func TestLookup_CaseInsensitiveAndNilSafe(t *testing.T) {
	snap, err := Parse(strings.NewReader(sampleFeed))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !snap.Has("  cve-2021-44228  ") {
		t.Error("Has should normalize case and whitespace")
	}
	if !snap.IsRansomware("cve-2021-44228") {
		t.Error("IsRansomware should normalize case")
	}

	var nilSnap *Snapshot
	if nilSnap.Has("CVE-2021-44228") || nilSnap.IsRansomware("CVE-2021-44228") || nilSnap.Len() != 0 {
		t.Error("nil snapshot must be safe and empty")
	}
	if cv, dr := nilSnap.Marker(); cv != "" || dr != "" {
		t.Error("nil snapshot marker must be empty")
	}
}

func TestParse_SkipsEmptyCVEIDs(t *testing.T) {
	feed := `{"catalogVersion":"v1","vulnerabilities":[
		{"cveID":"","knownRansomwareCampaignUse":"Known"},
		{"cveID":"CVE-2020-1234","knownRansomwareCampaignUse":"Unknown"}
	]}`
	snap, err := Parse(strings.NewReader(feed))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if snap.Len() != 1 {
		t.Errorf("Len = %d, want 1 (empty cveID skipped)", snap.Len())
	}
}

func TestParse_Errors(t *testing.T) {
	tests := map[string]string{
		"empty input":            "",
		"malformed json":         "{not json",
		"no vulnerabilities":     `{"catalogVersion":"v1","vulnerabilities":[]}`,
		"missing vulns key":      `{"catalogVersion":"v1"}`,
		"only empty cve entries": `{"vulnerabilities":[{"cveID":""}]}`,
	}
	for name, in := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(strings.NewReader(in)); err == nil {
				t.Errorf("expected error for %q, got nil", name)
			}
		})
	}
}

func TestLoad(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(sampleFeed))
	}))
	defer srv.Close()

	snap, err := Load(context.Background(), srv.Client(), srv.URL)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if snap.Len() != 3 {
		t.Errorf("Len = %d, want 3", snap.Len())
	}
}

func TestLoad_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	if _, err := Load(context.Background(), srv.Client(), srv.URL); err == nil {
		t.Error("expected error on 503 response")
	}
}

// TestParse_RealSampleFeed validates against the real catalog checked into
// test-n-learn/ when present. Skipped if the fixture is absent.
func TestParse_RealSampleFeed(t *testing.T) {
	const path = "../../../test-n-learn/known_exploited_vulnerabilities.json"
	f, err := os.Open(path)
	if err != nil {
		t.Skipf("real sample feed not available: %v", err)
	}
	defer f.Close()

	snap, err := Parse(f)
	if err != nil {
		t.Fatalf("Parse(real feed): %v", err)
	}
	if snap.Len() < 1000 {
		t.Errorf("real catalog parsed only %d CVEs, expected >1000", snap.Len())
	}
	if cv, _ := snap.Marker(); cv == "" {
		t.Error("real catalog should carry a catalogVersion marker")
	}
	// A known ransomware-flagged CVE from the fixture.
	if !snap.IsRansomware("CVE-2026-35273") {
		t.Error("CVE-2026-35273 should be flagged as known ransomware use")
	}
}
