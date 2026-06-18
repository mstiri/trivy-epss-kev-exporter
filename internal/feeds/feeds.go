// Package feeds runs the periodic refresh of a single bulk feed (EPSS or KEV).
//
// It implements TRIGGER B from CLAUDE.md: a feed refresher detects when the feed
// CONTENT changed — not merely that a refresh ran — and only then sweeps every
// report for re-enrichment. Content change is detected by the feed's marker
// (EPSS model_version/score_date, KEV catalogVersion/dateReleased); an unchanged
// marker means identical data, so we skip the (expensive) sweep.
//
// Graceful degradation: a failed refresh records the failure and KEEPS the last
// good snapshot in place — we never blank out enrichment because a fetch blipped.
package feeds

import (
	"context"
	"time"

	"k8s.io/klog/v2"
)

// Sink receives refresh outcomes for the self-metrics. Satisfied structurally by
// *metrics.Metrics, so this package does not import metrics.
type Sink interface {
	FeedRefreshSucceeded(feed string, at time.Time)
	FeedRefreshFailed(feed string)
}

// Result is the outcome of one successful load: the content Marker (for change
// detection) and Apply, which atomically installs the freshly parsed snapshot.
// Apply is separated from loading so the marker can be compared first, and so the
// snapshot swap is a trivial atomic pointer store.
type Result struct {
	Marker [2]string
	Apply  func()
}

// LoadFunc fetches and parses a feed and returns its Result. The app supplies one
// closure per feed (wrapping epss.Load / kev.Load and the atomic snapshot store).
type LoadFunc func(ctx context.Context) (Result, error)

// Refresher periodically refreshes one feed.
type Refresher struct {
	name     string
	interval time.Duration
	load     LoadFunc
	onChange func() // Trigger-B sweep; invoked only when content changed
	sink     Sink

	last [2]string
	have bool
}

// NewRefresher builds a refresher. name is the feed label ("epss"/"kev"),
// onChange is the sweep callback (may be nil in tests).
func NewRefresher(name string, interval time.Duration, load LoadFunc, onChange func(), sink Sink) *Refresher {
	return &Refresher{name: name, interval: interval, load: load, onChange: onChange, sink: sink}
}

// RefreshOnce performs one refresh cycle: load, install, and — only if the
// content marker CHANGED since the last success — fire the sweep. It reports
// whether content changed. On load failure it records the failure, keeps the
// previous snapshot, and returns the error (no sweep). Must be called from a
// single goroutine (Run guarantees this).
func (r *Refresher) RefreshOnce(ctx context.Context) (changed bool, err error) {
	res, err := r.load(ctx)
	if err != nil {
		r.sink.FeedRefreshFailed(r.name)
		return false, err
	}
	res.Apply()
	r.sink.FeedRefreshSucceeded(r.name, time.Now())

	firstLoad := !r.have
	changed = firstLoad || res.Marker != r.last
	r.last = res.Marker
	r.have = true

	switch {
	case firstLoad:
		klog.InfoS("feed loaded", "feed", r.name, "marker", res.Marker)
	case changed:
		klog.InfoS("feed content changed; re-enriching all reports", "feed", r.name, "marker", res.Marker)
	default:
		klog.V(4).InfoS("feed unchanged; skipping re-enrichment sweep", "feed", r.name, "marker", res.Marker)
	}

	if changed && r.onChange != nil {
		r.onChange()
	}
	return changed, nil
}

// Run does an immediate refresh (so feeds load ASAP and readiness can flip), then
// refreshes on the interval until ctx is cancelled. Errors are logged, not fatal
// — the last good snapshot keeps serving.
func (r *Refresher) Run(ctx context.Context) {
	if _, err := r.RefreshOnce(ctx); err != nil {
		klog.ErrorS(err, "initial feed refresh failed", "feed", r.name)
	}
	t := time.NewTicker(r.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, err := r.RefreshOnce(ctx); err != nil {
				klog.ErrorS(err, "feed refresh failed", "feed", r.name)
			}
		}
	}
}
