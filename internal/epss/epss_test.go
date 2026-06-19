package epss

import (
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

const sampleFeed = `#model_version:v2026.06.15,score_date:2026-06-16T12:03:06Z
cve,epss,percentile
CVE-1999-0001,0.03351,0.87094
CVE-1999-0002,0.27858,0.9784
CVE-2021-44228,0.94400,0.99999
`

func TestParse_HappyPath(t *testing.T) {
	snap, err := Parse(strings.NewReader(sampleFeed))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got, want := snap.Len(), 3; got != want {
		t.Errorf("Len = %d, want %d", got, want)
	}

	mv, sd := snap.Marker()
	if mv != "v2026.06.15" {
		t.Errorf("ModelVersion = %q, want v2026.06.15", mv)
	}
	// score_date contains colons; the preamble parser must keep them intact.
	if sd != "2026-06-16T12:03:06Z" {
		t.Errorf("ScoreDate = %q, want 2026-06-16T12:03:06Z", sd)
	}

	sc, ok := snap.Lookup("CVE-2021-44228")
	if !ok {
		t.Fatal("CVE-2021-44228 not found")
	}
	if sc.Score != 0.944 || sc.Percentile != 0.99999 {
		t.Errorf("got %+v, want {0.944 0.99999}", sc)
	}
}

func TestParse_NoPreamble(t *testing.T) {
	feed := "cve,epss,percentile\nCVE-2020-0001,0.5,0.5\n"
	snap, err := Parse(strings.NewReader(feed))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if mv, sd := snap.Marker(); mv != "" || sd != "" {
		t.Errorf("expected empty marker, got %q/%q", mv, sd)
	}
	if _, ok := snap.Lookup("CVE-2020-0001"); !ok {
		t.Error("CVE-2020-0001 not found")
	}
}

func TestLookup_CaseInsensitiveAndMissing(t *testing.T) {
	snap, err := Parse(strings.NewReader(sampleFeed))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if _, ok := snap.Lookup("  cve-2021-44228  "); !ok {
		t.Error("lookup should normalize case and whitespace")
	}
	if _, ok := snap.Lookup("CVE-0000-0000"); ok {
		t.Error("absent CVE should report ok=false")
	}
	// nil-safe.
	var nilSnap *Snapshot
	if _, ok := nilSnap.Lookup("CVE-2021-44228"); ok {
		t.Error("nil snapshot lookup should be false")
	}
}

func TestParse_ReorderedColumns(t *testing.T) {
	feed := "percentile,cve,epss\n0.9,CVE-2022-1234,0.42\n"
	snap, err := Parse(strings.NewReader(feed))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	sc, ok := snap.Lookup("CVE-2022-1234")
	if !ok || sc.Score != 0.42 || sc.Percentile != 0.9 {
		t.Errorf("reordered columns mis-parsed: %+v ok=%v", sc, ok)
	}
}

func TestParse_SkipsMalformedRows(t *testing.T) {
	feed := strings.Join([]string{
		"cve,epss,percentile",
		"CVE-2020-1111,0.1,0.2",       // good
		"CVE-2020-2222,notafloat,0.3", // bad score → skip
		"CVE-2020-3333,0.4",           // too few columns → skip
		",0.5,0.6",                    // empty cve → skip
		"CVE-2020-4444,0.7,0.8",       // good
		"",                            // blank line → skip
	}, "\n") + "\n"

	snap, err := Parse(strings.NewReader(feed))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got, want := snap.Len(), 2; got != want {
		t.Errorf("Len = %d, want %d (only the two well-formed rows)", got, want)
	}
	if _, ok := snap.Lookup("CVE-2020-1111"); !ok {
		t.Error("good row CVE-2020-1111 missing")
	}
	if _, ok := snap.Lookup("CVE-2020-4444"); !ok {
		t.Error("good row CVE-2020-4444 missing")
	}
}

func TestParse_Errors(t *testing.T) {
	tests := map[string]string{
		"empty input":          "",
		"bad header":           "foo,bar,baz\nCVE-1,0.1,0.2\n",
		"header but no rows":   "cve,epss,percentile\n",
		"all rows malformed":   "cve,epss,percentile\nCVE-1,x,y\n",
		"preamble but no data": "#model_version:v1,score_date:2026-01-01\n",
	}
	for name, in := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(strings.NewReader(in)); err == nil {
				t.Errorf("expected error for %q, got nil", name)
			}
		})
	}
}

func TestParsePreamble(t *testing.T) {
	tests := []struct {
		in       string
		wantMV   string
		wantDate string
	}{
		{"#model_version:v2026.06.15,score_date:2026-06-16T12:03:06Z", "v2026.06.15", "2026-06-16T12:03:06Z"},
		{"# model_version:v1 , score_date:2026-01-01T00:00:00Z ", "v1", "2026-01-01T00:00:00Z"},
		{"#score_date:2026-01-01,model_version:v9", "v9", "2026-01-01"},
		{"#unknown:foo", "", ""},
	}
	for _, tt := range tests {
		mv, sd := parsePreamble(tt.in)
		if mv != tt.wantMV || sd != tt.wantDate {
			t.Errorf("parsePreamble(%q) = %q/%q, want %q/%q", tt.in, mv, sd, tt.wantMV, tt.wantDate)
		}
	}
}

func TestLoad_PlainAndGzip(t *testing.T) {
	for _, gz := range []bool{false, true} {
		name := "plain"
		if gz {
			name = "gzip"
		}
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if gz {
					var buf bytes.Buffer
					zw := gzip.NewWriter(&buf)
					_, _ = zw.Write([]byte(sampleFeed))
					_ = zw.Close()
					_, _ = w.Write(buf.Bytes())
					return
				}
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
		})
	}
}

func TestLoad_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	defer srv.Close()
	if _, err := Load(context.Background(), srv.Client(), srv.URL); err == nil {
		t.Error("expected error on 500 response")
	}
}

// TestParse_RealSampleFeed validates against the real feed checked into
// test-n-learn/ when present. Skipped if the fixture is absent.
func TestParse_RealSampleFeed(t *testing.T) {
	const path = "../../../test-n-learn/epss_scores-current.csv"
	f, err := os.Open(path)
	if err != nil {
		t.Skipf("real sample feed not available: %v", err)
	}
	defer f.Close()

	snap, err := Parse(f)
	if err != nil {
		t.Fatalf("Parse(real feed): %v", err)
	}
	if snap.Len() < 100_000 {
		t.Errorf("real feed parsed only %d CVEs, expected >100k", snap.Len())
	}
	if mv, _ := snap.Marker(); mv == "" {
		t.Error("real feed should carry a model_version marker")
	}
	// A known row from the fixture's tail.
	if sc, ok := snap.Lookup("CVE-2026-9999"); !ok {
		t.Error("expected CVE-2026-9999 in real feed")
	} else if sc.Score <= 0 || sc.Score > 1 || sc.Percentile <= 0 || sc.Percentile > 1 {
		t.Errorf("CVE-2026-9999 out of range: %+v", sc)
	}
}
