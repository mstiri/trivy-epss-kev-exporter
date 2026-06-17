// Package enrich is the PURE core of the exporter: given a parsed
// VulnerabilityReport and the current EPSS/KEV snapshots, it produces the exact
// set of metric series (label-tuples + values) the report should contribute.
//
// It is the single idempotent operation referenced in CLAUDE.md as
// enrich(report). It has no cluster, no I/O, and no Prometheus dependency — the
// metric layer (step 4) turns these Series into gauge Set() calls, and the
// worker (step 6) diffs them against the per-report series map to add/remove
// series. Keeping it pure makes it the highest-value thing to unit-test.
package enrich

import (
	"strings"

	"github.com/mstiri/trivy-epss-kev-exporter/internal/epss"
	"github.com/mstiri/trivy-epss-kev-exporter/internal/kev"
	"github.com/mstiri/trivy-epss-kev-exporter/internal/report"
)

// LabelNames is the canonical, ordered label set for the vuln metrics. Labels.Values
// returns values in this exact order, so the metric layer can register a
// GaugeVec with LabelNames and feed it Values() positionally.
var LabelNames = []string{
	"cve",
	"namespace",
	"workload",
	"workload_kind",
	"container",
	"resource",
	"severity",
}

// Labels is one fully-resolved label-tuple. It is an all-string comparable
// struct, so it doubles as the map key for the per-report series set — that is
// what gives within-report de-dup for free (the operator can emit the same
// vuln twice; identical tuples collapse).
type Labels struct {
	CVE          string
	Namespace    string
	Workload     string
	WorkloadKind string
	Container    string
	Resource     string
	Severity     string
}

// Values returns the label values in LabelNames order.
func (l Labels) Values() []string {
	return []string{
		l.CVE,
		l.Namespace,
		l.Workload,
		l.WorkloadKind,
		l.Container,
		l.Resource,
		l.Severity,
	}
}

// Series is one enriched label-tuple plus every gauge value for it. All four
// values are always populated: EPSS-absent CVEs carry 0 (not omitted), and KEV
// is 0/1 by definition — see CLAUDE.md "Missing-data semantics".
type Series struct {
	Labels         Labels
	EPSSScore      float64 // 0.0 when the CVE is absent from the EPSS feed
	EPSSPercentile float64 // 0.0 when the CVE is absent from the EPSS feed
	KEV            float64 // 1 if in the KEV catalog, else 0
	KEVRansomware  float64 // 1 if KEV knownRansomwareCampaignUse == "Known", else 0
}

// Report enriches every vulnerability in r against the EPSS/KEV snapshots and
// returns the de-duplicated series the report contributes. The workload w is the
// already-RESOLVED owner (the controller applies ReplicaSet→Deployment roll-up
// before calling; pass r.Workload() directly for the no-roll-up case). Keeping w
// an explicit input is what lets this core stay pure and cluster-free. The
// snapshots are nil-safe (a not-yet-loaded feed enriches to zeros). Order follows
// first appearance in the report; duplicates after the first are dropped.
func Report(r *report.VulnerabilityReport, w report.Workload, e *epss.Snapshot, k *kev.Snapshot) []Series {
	if r == nil {
		return nil
	}

	seen := make(map[Labels]struct{}, len(r.Report.Vulnerabilities))
	out := make([]Series, 0, len(r.Report.Vulnerabilities))

	for _, v := range r.Report.Vulnerabilities {
		cve := normalizeCVE(v.VulnerabilityID)
		if cve == "" {
			continue
		}
		lbl := Labels{
			CVE:          cve,
			Namespace:    w.Namespace,
			Workload:     w.Name,
			WorkloadKind: w.Kind,
			Container:    w.Container,
			Resource:     v.Resource,
			Severity:     normalizeSeverity(v.Severity),
		}
		if _, dup := seen[lbl]; dup {
			continue
		}
		seen[lbl] = struct{}{}

		// Lookup's ok=false yields the zero Score{0,0}, which is exactly the
		// "emit 0" behavior we want for unscored CVEs.
		sc, _ := e.Lookup(cve)
		out = append(out, Series{
			Labels:         lbl,
			EPSSScore:      sc.Score,
			EPSSPercentile: sc.Percentile,
			KEV:            boolToFloat(k.Has(cve)),
			KEVRansomware:  boolToFloat(k.IsRansomware(cve)),
		})
	}
	return out
}

func normalizeCVE(s string) string {
	return strings.ToUpper(strings.TrimSpace(s))
}

// normalizeSeverity upper-cases the CRD's severity and defaults the empty case
// to UNKNOWN so the label is never blank.
func normalizeSeverity(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	if s == "" {
		return "UNKNOWN"
	}
	return s
}

func boolToFloat(b bool) float64 {
	if b {
		return 1
	}
	return 0
}
