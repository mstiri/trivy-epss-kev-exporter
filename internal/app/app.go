// Package app wires the pure layers to the cluster layer: it owns the live
// EPSS/KEV snapshots, the reconcile function (enrich → metrics), the two feed
// refreshers, and the readiness signal. It is the meeting point of the two
// triggers from CLAUDE.md — informer events (Trigger A, via the controller) and
// feed content changes (Trigger B, via the refreshers' EnqueueAll sweep) — both
// funnelled through the controller's single workqueue into reconcile.
package app

import (
	"context"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mstiri/trivy-epss-kev-exporter/internal/controller"
	"github.com/mstiri/trivy-epss-kev-exporter/internal/enrich"
	"github.com/mstiri/trivy-epss-kev-exporter/internal/epss"
	"github.com/mstiri/trivy-epss-kev-exporter/internal/feeds"
	"github.com/mstiri/trivy-epss-kev-exporter/internal/kev"
	"github.com/mstiri/trivy-epss-kev-exporter/internal/metrics"
	"github.com/mstiri/trivy-epss-kev-exporter/internal/report"
)

// Default bulk feed URLs (overridable via Config / flags).
const (
	DefaultEPSSURL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
	DefaultKEVURL  = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)

// Config is the runtime configuration (populated from flags/env in cmd).
type Config struct {
	EPSSURL             string
	KEVURL              string
	FeedRefreshInterval time.Duration
	FeedHTTPTimeout     time.Duration
	EnableRansomware    bool
	Namespaces          []string
	ResyncInterval      time.Duration
	Workers             int
	EnableRollup        bool
	UserAgent           string
}

func withDefaults(c Config) Config {
	if c.EPSSURL == "" {
		c.EPSSURL = DefaultEPSSURL
	}
	if c.KEVURL == "" {
		c.KEVURL = DefaultKEVURL
	}
	if c.FeedRefreshInterval <= 0 {
		c.FeedRefreshInterval = 24 * time.Hour
	}
	if c.FeedHTTPTimeout <= 0 {
		c.FeedHTTPTimeout = 2 * time.Minute
	}
	if c.UserAgent == "" {
		c.UserAgent = "trivy-epss-kev-exporter"
	}
	return c
}

// snapshots holds the live feed data for lock-free reads by the reconcile
// worker; the refreshers swap the pointers atomically. The loaded flags gate
// readiness ("each feed has loaded at least once").
type snapshots struct {
	epss       atomic.Pointer[epss.Snapshot]
	kev        atomic.Pointer[kev.Snapshot]
	epssLoaded atomic.Bool
	kevLoaded  atomic.Bool
}

func (s *snapshots) ready() bool { return s.epssLoaded.Load() && s.kevLoaded.Load() }

// App is the assembled exporter (sans HTTP server, added in step 7).
type App struct {
	cfg        Config
	metrics    *metrics.Metrics
	snap       *snapshots
	ctrl       *controller.Controller
	client     *http.Client
	refreshers []*feeds.Refresher

	cacheSynced atomic.Bool
}

// New assembles the app from already-built clients (injected so the app is
// testable with fakes). It constructs the metrics, the controller (with the
// reconcile callback), and the two feed refreshers.
func New(clients *controller.Clients, cfg Config) (*App, error) {
	cfg = withDefaults(cfg)
	a := &App{
		cfg:     cfg,
		metrics: metrics.New(metrics.Options{EnableRansomware: cfg.EnableRansomware}),
		snap:    &snapshots{},
		client:  newHTTPClient(cfg.FeedHTTPTimeout, cfg.UserAgent),
	}

	ctrl, err := controller.New(clients, a.reconcile, a.onSynced, controller.Options{
		Namespaces:     cfg.Namespaces,
		ResyncInterval: cfg.ResyncInterval,
		Workers:        cfg.Workers,
		EnableRollup:   cfg.EnableRollup,
	})
	if err != nil {
		return nil, err
	}
	a.ctrl = ctrl

	a.refreshers = []*feeds.Refresher{
		feeds.NewRefresher("epss", cfg.FeedRefreshInterval, a.loadEPSS, a.ctrl.EnqueueAll, a.metrics),
		feeds.NewRefresher("kev", cfg.FeedRefreshInterval, a.loadKEV, a.ctrl.EnqueueAll, a.metrics),
	}
	return a, nil
}

// Metrics exposes the metrics registry holder (for the step-7 HTTP handler).
func (a *App) Metrics() *metrics.Metrics { return a.metrics }

// Ready reports readiness: informer cache synced AND both feeds loaded once.
func (a *App) Ready() bool { return a.cacheSynced.Load() && a.snap.ready() }

// reconcile is the single idempotent operation, invoked by the controller's
// worker for every changed/swept report key. Missing report ⇒ drop its series.
func (a *App) reconcile(key string, rep *report.VulnerabilityReport, w report.Workload, exists bool) error {
	if !exists {
		a.metrics.DeleteReport(key)
		return nil
	}
	series := enrich.Report(rep, w, a.snap.epss.Load(), a.snap.kev.Load())
	a.metrics.SetReport(key, series)
	return nil
}

// onSynced reflects informer cache-sync state into both readiness and the
// cache_synced self-metric.
func (a *App) onSynced(synced bool) {
	a.cacheSynced.Store(synced)
	a.metrics.SetCacheSynced(synced)
}

func (a *App) loadEPSS(ctx context.Context) (feeds.Result, error) {
	snap, err := epss.Load(ctx, a.client, a.cfg.EPSSURL)
	if err != nil {
		return feeds.Result{}, err
	}
	mv, sd := snap.Marker()
	return feeds.Result{
		Marker: [2]string{mv, sd},
		Apply: func() {
			a.snap.epss.Store(snap)
			a.snap.epssLoaded.Store(true)
		},
	}, nil
}

func (a *App) loadKEV(ctx context.Context) (feeds.Result, error) {
	snap, err := kev.Load(ctx, a.client, a.cfg.KEVURL)
	if err != nil {
		return feeds.Result{}, err
	}
	cv, dr := snap.Marker()
	return feeds.Result{
		Marker: [2]string{cv, dr},
		Apply: func() {
			a.snap.kev.Store(snap)
			a.snap.kevLoaded.Store(true)
		},
	}, nil
}

// Run starts the controller and the feed refreshers and blocks until ctx is
// cancelled. A controller error (e.g. cache sync failure) cancels everything and
// is returned.
func (a *App) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	errCh := make(chan error, 1)

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := a.ctrl.Run(ctx); err != nil {
			select {
			case errCh <- err:
			default:
			}
			cancel()
		}
	}()

	for _, r := range a.refreshers {
		wg.Add(1)
		go func(r *feeds.Refresher) {
			defer wg.Done()
			r.Run(ctx)
		}(r)
	}

	<-ctx.Done()
	wg.Wait()
	select {
	case err := <-errCh:
		return err
	default:
		return nil
	}
}

// feedTransport sets headers on outbound feed requests. CISA's CDN requires
// Accept: application/json (returns 403 without it); User-Agent avoids blank-UA
// rejections from other hosts.
type feedTransport struct {
	ua   string
	next http.RoundTripper
}

func (t *feedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", t.ua)
	}
	if req.Header.Get("Accept") == "" {
		req.Header.Set("Accept", "application/json, application/octet-stream, */*")
	}
	return t.next.RoundTrip(req)
}

func newHTTPClient(timeout time.Duration, ua string) *http.Client {
	base := http.DefaultTransport.(*http.Transport).Clone()
	return &http.Client{Timeout: timeout, Transport: &feedTransport{ua: ua, next: base}}
}
