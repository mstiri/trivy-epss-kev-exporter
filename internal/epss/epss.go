// Package epss loads and parses the FIRST/EPSS bulk score feed.
//
// The feed is a gzipped CSV served as a single bulk file (NOT the per-CVE API):
//
//	#model_version:v2026.06.15,score_date:2026-06-16T12:03:06Z
//	cve,epss,percentile
//	CVE-1999-0001,0.03351,0.87094
//	...
//
// The first line is an optional `#`-prefixed preamble carrying the model
// version and score date. We surface those as Snapshot.ModelVersion /
// Snapshot.ScoreDate so the feed refresher can cheaply detect whether the feed
// CONTENT changed (Trigger B) without diffing ~300k rows: an unchanged marker
// pair means unchanged data, so no re-enrichment sweep is needed.
//
// Parse is pure (io.Reader in, Snapshot out) and is the unit-tested core.
// Load is the thin HTTP+gzip wrapper around it.
package epss

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// Score is the EPSS data for a single CVE.
type Score struct {
	// Score is the EPSS exploitation probability in [0.0, 1.0]. This is a
	// metric VALUE, never a label — it changes daily.
	Score float64
	// Percentile is the CVE's rank among all scored CVEs in [0.0, 1.0].
	Percentile float64
}

// Snapshot is one fully parsed EPSS feed held in memory.
type Snapshot struct {
	// Scores is keyed by normalized (upper-cased, trimmed) CVE ID.
	Scores map[string]Score
	// ModelVersion / ScoreDate come from the "#" preamble. Empty if the feed
	// carried no preamble. Used for content-change detection.
	ModelVersion string
	ScoreDate    string
}

// Lookup returns the EPSS score for a CVE. The second result is false when the
// CVE is absent from the feed — callers emit epss_score / epss_percentile as 0
// in that case (see CLAUDE.md "Missing-data semantics").
func (s *Snapshot) Lookup(cve string) (Score, bool) {
	if s == nil {
		return Score{}, false
	}
	sc, ok := s.Scores[normalizeCVE(cve)]
	return sc, ok
}

// Len reports how many CVEs the snapshot holds.
func (s *Snapshot) Len() int {
	if s == nil {
		return 0
	}
	return len(s.Scores)
}

// Marker returns the (model_version, score_date) pair used for change
// detection. Equal markers across two refreshes ⇒ identical data ⇒ skip sweep.
func (s *Snapshot) Marker() (modelVersion, scoreDate string) {
	if s == nil {
		return "", ""
	}
	return s.ModelVersion, s.ScoreDate
}

// Parse reads a DECOMPRESSED EPSS CSV stream into a Snapshot. It tolerates a
// missing preamble and skips malformed data rows (graceful degradation — one
// bad row must not discard the whole feed). It errors only when the stream is
// structurally unusable: no header, an unrecognized header, or zero valid rows.
func Parse(r io.Reader) (*Snapshot, error) {
	br := bufio.NewReader(r)
	snap := &Snapshot{Scores: make(map[string]Score)}

	// The preamble line starts with '#'. encoding/csv would treat it as data,
	// so peek and consume it ourselves before handing the rest to the reader.
	if b, err := br.Peek(1); err == nil && len(b) == 1 && b[0] == '#' {
		line, err := br.ReadString('\n')
		if err != nil && err != io.EOF {
			return nil, fmt.Errorf("epss: reading preamble: %w", err)
		}
		snap.ModelVersion, snap.ScoreDate = parsePreamble(line)
	}

	cr := csv.NewReader(br)
	cr.FieldsPerRecord = -1 // rows are validated by column index, not a fixed count
	cr.ReuseRecord = true   // ~300k rows; avoid per-row allocation

	header, err := cr.Read()
	if err != nil {
		return nil, fmt.Errorf("epss: reading header: %w", err)
	}
	cveCol, epssCol, pctCol, err := columnIndices(header)
	if err != nil {
		return nil, err
	}
	maxCol := max(cveCol, max(epssCol, pctCol))

	for {
		rec, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			// A malformed line (e.g. bad quoting) — skip it, keep going.
			if errors.Is(err, csv.ErrFieldCount) {
				continue
			}
			var pe *csv.ParseError
			if errors.As(err, &pe) {
				continue
			}
			return nil, fmt.Errorf("epss: reading rows: %w", err)
		}
		if len(rec) <= maxCol {
			continue
		}
		score, err1 := strconv.ParseFloat(strings.TrimSpace(rec[epssCol]), 64)
		pct, err2 := strconv.ParseFloat(strings.TrimSpace(rec[pctCol]), 64)
		if err1 != nil || err2 != nil {
			continue
		}
		cve := normalizeCVE(rec[cveCol])
		if cve == "" {
			continue
		}
		snap.Scores[cve] = Score{Score: score, Percentile: pct}
	}

	if len(snap.Scores) == 0 {
		return nil, errors.New("epss: no valid rows parsed")
	}
	return snap, nil
}

// Load fetches the EPSS feed over HTTP, transparently gunzips it (detected by
// magic bytes, so it works whether or not the server/URL advertises gzip), and
// parses it. The caller owns the http.Client (timeouts, proxy, User-Agent).
func Load(ctx context.Context, client *http.Client, url string) (*Snapshot, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("epss: building request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("epss: fetching %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("epss: fetching %s: unexpected status %s", url, resp.Status)
	}

	reader, err := maybeGunzip(resp.Body)
	if err != nil {
		return nil, err
	}
	return Parse(reader)
}

// maybeGunzip wraps r in a gzip reader when the stream begins with the gzip
// magic bytes (0x1f 0x8b); otherwise it returns the stream unchanged.
func maybeGunzip(r io.Reader) (io.Reader, error) {
	br := bufio.NewReader(r)
	magic, err := br.Peek(2)
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("epss: peeking stream: %w", err)
	}
	if len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		gz, err := gzip.NewReader(br)
		if err != nil {
			return nil, fmt.Errorf("epss: gzip: %w", err)
		}
		return gz, nil
	}
	return br, nil
}

// parsePreamble extracts model_version and score_date from a line like
//
//	#model_version:v2026.06.15,score_date:2026-06-16T12:03:06Z
//
// Values (notably the RFC3339 score_date) contain colons, so each field is
// split on its FIRST colon only. Unknown keys are ignored.
func parsePreamble(line string) (modelVersion, scoreDate string) {
	line = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "#"))
	for field := range strings.SplitSeq(line, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(field), ":")
		if !ok {
			continue
		}
		switch strings.TrimSpace(k) {
		case "model_version":
			modelVersion = strings.TrimSpace(v)
		case "score_date":
			scoreDate = strings.TrimSpace(v)
		}
	}
	return modelVersion, scoreDate
}

// columnIndices locates the cve/epss/percentile columns from the header row so
// we are robust to column reordering. Matching is case-insensitive.
func columnIndices(header []string) (cve, epss, pct int, err error) {
	cve, epss, pct = -1, -1, -1
	for i, h := range header {
		switch strings.ToLower(strings.TrimSpace(h)) {
		case "cve":
			cve = i
		case "epss":
			epss = i
		case "percentile":
			pct = i
		}
	}
	if cve < 0 || epss < 0 || pct < 0 {
		return 0, 0, 0, fmt.Errorf("epss: unrecognized header %q (need cve,epss,percentile)", strings.Join(header, ","))
	}
	return cve, epss, pct, nil
}

func normalizeCVE(s string) string {
	return strings.ToUpper(strings.TrimSpace(s))
}
