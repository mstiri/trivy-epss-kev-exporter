// Package kev loads and parses the CISA Known Exploited Vulnerabilities feed.
//
// The feed is a single JSON document (NOT gzipped, unlike EPSS):
//
//	{
//	  "catalogVersion": "2026.06.15",
//	  "dateReleased": "2026-06-15T19:00:14.5797Z",
//	  "count": 1621,
//	  "vulnerabilities": [
//	    {"cveID": "CVE-2026-54420", "knownRansomwareCampaignUse": "Unknown", ...},
//	    ...
//	  ]
//	}
//
// We keep only what the metric contract needs: the SET of CVEs in the catalog
// (drives trivy_vuln_kev) and the subset flagged for ransomware campaign use
// (drives trivy_vuln_kev_ransomware). catalogVersion / dateReleased are
// surfaced via Marker() as the cheap Trigger-B change-detection signal.
//
// Parse is pure (io.Reader in, Snapshot out) and is the unit-tested core.
// Load is the thin HTTP wrapper around it.
package kev

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Snapshot is one fully parsed KEV catalog held in memory.
type Snapshot struct {
	// present holds every CVE in the catalog, keyed by normalized CVE ID.
	present map[string]struct{}
	// ransomware holds the subset where knownRansomwareCampaignUse == "Known".
	ransomware map[string]struct{}
	// CatalogVersion / DateReleased come from the feed's top-level fields and
	// drive content-change detection. Empty if absent.
	CatalogVersion string
	DateReleased   string
}

// Has reports whether the CVE is present in the KEV catalog. This is the
// trivy_vuln_kev value: true ⇒ 1, false ⇒ 0.
func (s *Snapshot) Has(cve string) bool {
	if s == nil {
		return false
	}
	_, ok := s.present[normalizeCVE(cve)]
	return ok
}

// IsRansomware reports whether the CVE is flagged as used in a known ransomware
// campaign (knownRansomwareCampaignUse == "Known"). Drives
// trivy_vuln_kev_ransomware. Always false for CVEs not in the catalog.
func (s *Snapshot) IsRansomware(cve string) bool {
	if s == nil {
		return false
	}
	_, ok := s.ransomware[normalizeCVE(cve)]
	return ok
}

// Len reports how many CVEs the catalog holds.
func (s *Snapshot) Len() int {
	if s == nil {
		return 0
	}
	return len(s.present)
}

// Marker returns the (catalogVersion, dateReleased) pair used for change
// detection. Equal markers across two refreshes ⇒ identical data ⇒ skip sweep.
func (s *Snapshot) Marker() (catalogVersion, dateReleased string) {
	if s == nil {
		return "", ""
	}
	return s.CatalogVersion, s.DateReleased
}

// feed mirrors only the fields we consume; encoding/json ignores the rest.
type feed struct {
	CatalogVersion  string `json:"catalogVersion"`
	DateReleased    string `json:"dateReleased"`
	Vulnerabilities []struct {
		CveID                      string `json:"cveID"`
		KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`
	} `json:"vulnerabilities"`
}

// Parse reads a KEV JSON stream into a Snapshot. It errors when the JSON is
// malformed or carries zero usable entries (the real catalog always holds
// 1000+, so an empty set signals a corrupt or truncated feed, not a valid one).
func Parse(r io.Reader) (*Snapshot, error) {
	var f feed
	if err := json.NewDecoder(r).Decode(&f); err != nil {
		return nil, fmt.Errorf("kev: decoding json: %w", err)
	}

	snap := &Snapshot{
		present:        make(map[string]struct{}, len(f.Vulnerabilities)),
		ransomware:     make(map[string]struct{}),
		CatalogVersion: f.CatalogVersion,
		DateReleased:   f.DateReleased,
	}
	for _, v := range f.Vulnerabilities {
		cve := normalizeCVE(v.CveID)
		if cve == "" {
			continue
		}
		snap.present[cve] = struct{}{}
		// CISA uses the literal strings "Known" / "Unknown"; match loosely.
		if strings.EqualFold(strings.TrimSpace(v.KnownRansomwareCampaignUse), "Known") {
			snap.ransomware[cve] = struct{}{}
		}
	}

	if len(snap.present) == 0 {
		return nil, fmt.Errorf("kev: no usable entries parsed")
	}
	return snap, nil
}

// Load fetches the KEV feed over HTTP and parses it. The caller owns the
// http.Client (timeouts, proxy, User-Agent). Go's transport transparently
// handles any Content-Encoding: gzip the server applies, so no manual gunzip is
// needed here (the KEV feed is served as plain JSON).
func Load(ctx context.Context, client *http.Client, url string) (*Snapshot, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("kev: building request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("kev: fetching %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("kev: fetching %s: unexpected status %s", url, resp.Status)
	}
	return Parse(resp.Body)
}

func normalizeCVE(s string) string {
	return strings.ToUpper(strings.TrimSpace(s))
}
