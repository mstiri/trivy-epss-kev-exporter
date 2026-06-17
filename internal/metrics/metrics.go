// Package metrics owns the Prometheus registry, the stable vuln gauges, the
// operability self-metrics, and the per-report series bookkeeping that gives the
// "replace, not upsert" lifecycle from CLAUDE.md.
//
// The worker (step 6) drives this with two calls:
//
//	SetReport(uid, series)  // re-enrich: set the report's series, drop its stale ones
//	DeleteReport(uid)       // OnDelete: drop everything the report owned
//
// Series ownership is REFERENCE-COUNTED across reports. That matters once
// Deployment roll-up (step 5) lands: the old and new ReplicaSet reports during a
// rollout both roll up to the same workload and can own the same label-tuple, so
// a tuple's gauge is removed only when the last report referencing it goes away.
// Values stay consistent because identical tuple ⇒ identical CVE ⇒ identical
// enrichment.
package metrics

import (
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	versioncollector "github.com/prometheus/client_golang/prometheus/collectors/version"

	"github.com/mstiri/trivy-epss-kev-exporter/internal/enrich"
)

// Options configures which optional metrics are emitted.
type Options struct {
	// EnableRansomware registers and emits trivy_vuln_kev_ransomware.
	EnableRansomware bool
}

// Metrics holds every collector plus the series bookkeeping. All exported
// methods are safe for concurrent use: distinct report keys can be processed by
// different workers, and they all mutate the shared series/refcount maps.
type Metrics struct {
	reg *prometheus.Registry

	// Vuln gauges — one series per (cve × workload × container × resource),
	// labelled by enrich.LabelNames.
	epssScore      *prometheus.GaugeVec
	epssPercentile *prometheus.GaugeVec
	kev            *prometheus.GaugeVec
	kevRansomware  *prometheus.GaugeVec // nil when EnableRansomware is false

	// Self-metrics (operability).
	feedLastSuccess  *prometheus.GaugeVec
	feedFailures     *prometheus.CounterVec
	reportsProcessed prometheus.Counter
	cvesEnriched     prometheus.Counter
	cacheSynced      prometheus.Gauge

	mu     sync.Mutex
	owners map[string]map[enrich.Labels]struct{} // reportUID → tuples it currently contributes
	refs   map[enrich.Labels]int                 // tuple → number of reports contributing it
}

// New builds the registry, registers all collectors, and returns the Metrics.
// It uses a private registry (not the global default) so it is test-isolated and
// cannot collide with stray registrations elsewhere.
func New(opts Options) *Metrics {
	reg := prometheus.NewRegistry()
	m := &Metrics{
		reg:    reg,
		owners: make(map[string]map[enrich.Labels]struct{}),
		refs:   make(map[enrich.Labels]int),
	}

	m.epssScore = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "trivy_vuln_epss_score",
		Help: "EPSS exploitation probability (0.0-1.0) for a CVE affecting a workload; 0 when the CVE is absent from the EPSS feed.",
	}, enrich.LabelNames)
	m.epssPercentile = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "trivy_vuln_epss_percentile",
		Help: "EPSS percentile (0.0-1.0) for a CVE affecting a workload; 0 when the CVE is absent from the EPSS feed.",
	}, enrich.LabelNames)
	m.kev = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "trivy_vuln_kev",
		Help: "1 if the CVE is in the CISA KEV catalog, else 0.",
	}, enrich.LabelNames)

	m.feedLastSuccess = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "trivy_exporter_feed_last_success_timestamp",
		Help: "Unix timestamp (seconds) of the last successful refresh of a feed.",
	}, []string{"feed"})
	m.feedFailures = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "trivy_exporter_feed_refresh_failures_total",
		Help: "Total failed refresh attempts per feed.",
	}, []string{"feed"})
	m.reportsProcessed = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "trivy_exporter_reports_processed_total",
		Help: "Total VulnerabilityReport enrichment passes processed.",
	})
	m.cvesEnriched = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "trivy_exporter_cves_enriched_total",
		Help: "Total CVE series enriched across all processing passes.",
	})
	m.cacheSynced = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "trivy_exporter_cache_synced",
		Help: "1 once the informer cache has synced, else 0.",
	})

	toRegister := []prometheus.Collector{
		m.epssScore, m.epssPercentile, m.kev,
		m.feedLastSuccess, m.feedFailures,
		m.reportsProcessed, m.cvesEnriched, m.cacheSynced,
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		// trivy_exporter_build_info{version,revision,branch,goversion} — the
		// ecosystem-standard build-provenance gauge, fed by prometheus/common/version
		// vars stamped at link time (see the Dockerfile -ldflags).
		versioncollector.NewCollector("trivy_exporter"),
	}
	if opts.EnableRansomware {
		m.kevRansomware = prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "trivy_vuln_kev_ransomware",
			Help: "1 if the CVE's KEV entry has knownRansomwareCampaignUse == \"Known\", else 0.",
		}, enrich.LabelNames)
		toRegister = append(toRegister, m.kevRansomware)
	}
	reg.MustRegister(toRegister...)
	return m
}

// Registry exposes the registry so the HTTP server (step 7) can serve it.
func (m *Metrics) Registry() *prometheus.Registry { return m.reg }

// SetReport reconciles all series for a report UID to exactly the given set:
// it sets the gauges for every series, then deletes any series this report used
// to own but no longer does (decrementing refcounts; a gauge is removed only at
// refcount 0). Passing an empty slice is equivalent to DeleteReport(uid).
func (m *Metrics) SetReport(uid string, series []enrich.Series) {
	m.mu.Lock()
	defer m.mu.Unlock()

	newSet := make(map[enrich.Labels]struct{}, len(series))
	for _, s := range series {
		vals := s.Labels.Values()
		m.epssScore.WithLabelValues(vals...).Set(s.EPSSScore)
		m.epssPercentile.WithLabelValues(vals...).Set(s.EPSSPercentile)
		m.kev.WithLabelValues(vals...).Set(s.KEV)
		if m.kevRansomware != nil {
			m.kevRansomware.WithLabelValues(vals...).Set(s.KEVRansomware)
		}
		if _, dup := newSet[s.Labels]; !dup {
			newSet[s.Labels] = struct{}{}
		}
	}

	old := m.owners[uid]
	// Reference newly-owned tuples.
	for lbl := range newSet {
		if _, had := old[lbl]; !had {
			m.refs[lbl]++
		}
	}
	// Release tuples this report dropped.
	for lbl := range old {
		if _, still := newSet[lbl]; !still {
			m.release(lbl)
		}
	}

	if len(newSet) == 0 {
		delete(m.owners, uid)
	} else {
		m.owners[uid] = newSet
	}

	m.reportsProcessed.Inc()
	m.cvesEnriched.Add(float64(len(newSet)))
}

// DeleteReport removes every series the report owned (decrementing refcounts).
func (m *Metrics) DeleteReport(uid string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for lbl := range m.owners[uid] {
		m.release(lbl)
	}
	delete(m.owners, uid)
}

// release decrements a tuple's refcount and deletes its gauges at 0. Caller
// holds m.mu.
func (m *Metrics) release(lbl enrich.Labels) {
	m.refs[lbl]--
	if m.refs[lbl] > 0 {
		return
	}
	delete(m.refs, lbl)
	vals := lbl.Values()
	m.epssScore.DeleteLabelValues(vals...)
	m.epssPercentile.DeleteLabelValues(vals...)
	m.kev.DeleteLabelValues(vals...)
	if m.kevRansomware != nil {
		m.kevRansomware.DeleteLabelValues(vals...)
	}
}

// --- self-metric setters (driven by the feed refreshers / informer glue) ---

// FeedRefreshSucceeded records a successful refresh timestamp for a feed.
func (m *Metrics) FeedRefreshSucceeded(feed string, at time.Time) {
	m.feedLastSuccess.WithLabelValues(feed).Set(float64(at.Unix()))
}

// FeedRefreshFailed increments the failure counter for a feed.
func (m *Metrics) FeedRefreshFailed(feed string) {
	m.feedFailures.WithLabelValues(feed).Inc()
}

// SetCacheSynced reflects informer cache-sync state (1 synced, 0 not).
func (m *Metrics) SetCacheSynced(synced bool) {
	if synced {
		m.cacheSynced.Set(1)
		return
	}
	m.cacheSynced.Set(0)
}
