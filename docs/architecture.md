# Architecture overview

A quick map of the codebase for new contributors. The full design rationale,
metric contract, and label cardinality rules live in [`CLAUDE.md`](../CLAUDE.md).

---

## What this exporter does

```
Trivy Operator ──(VulnerabilityReport CRDs)──▶ informer ──▶ enrich(CVE) ──▶ /metrics
                                                              ▲   ▲
                       EPSS bulk CSV ─(daily)─────────────────┘   │
                       CISA KEV JSON ─(daily)─────────────────────┘
```

Both feeds are bulk-loaded and cached in memory once per day. All enrichment
is a local map lookup — no per-CVE API calls at scrape time.

Re-enrichment is triggered by **two independent events** (see `CLAUDE.md §
Architecture` for the rationale):

- **Trigger A** — a `VulnerabilityReport` CRD is created, updated, or deleted.
- **Trigger B** — a feed's content changed on refresh (new EPSS scores, new KEV
  entries). This re-enriches every report in the cluster.

Both triggers funnel into a single workqueue so enrichment is serialized per
report key and deduped automatically.

---

## Package map

```
cmd/trivy-epss-kev-exporter/
  main.go           Entry point. Parses flags, wires all packages together,
                    handles SIGTERM graceful shutdown.

internal/
  epss/             Downloads + parses the EPSS gzipped CSV feed.
                    Pure: no Kubernetes, no Prometheus dependency.

  kev/              Downloads + parses the CISA KEV JSON feed.
                    Pure: no Kubernetes, no Prometheus dependency.

  report/           Minimal local type for the VulnerabilityReport CRD.
                    Extracts workload identity from operator labels.
                    Pure: no I/O.

  enrich/           The core: (report + EPSS snapshot + KEV snapshot) → []Series.
                    De-duplicates CVEs within a report. Nil-safe on snapshots.
                    Pure: no I/O, no cluster, no Prometheus.

  metrics/          Prometheus registry + gauge lifecycle.
                    Tracks which series each report owns so stale series
                    (fixed CVEs) are deleted, not left to accumulate.
                    Reference-counts shared series across reports (needed during
                    Deployment rollouts when two ReplicaSet reports coexist).

  feeds/            Timer-driven feed refresh. Compares content markers
                    (EPSS model_version/score_date, KEV catalogVersion) to
                    detect real changes and skip unnecessary sweeps.

  controller/       client-go DynamicSharedInformerFactory + workqueue.
                    Watches VulnerabilityReports cluster-wide.
                    Optionally watches ReplicaSets to roll RS→Deployment
                    workload labels up to the stable Deployment name.
                    Dispatches to a ReconcileFunc (injected by app/).

  app/              Glue layer. Owns the live EPSS/KEV snapshots (atomic
                    pointers for lock-free reads). Wires controller ↔ feeds.
                    Implements the ReconcileFunc: enrich → set gauges.
                    Owns the readiness signal (feeds loaded + cache synced).

  server/           Tiny net/http server.
                    /metrics  — Prometheus scrape endpoint.
                    /healthz  — liveness (always 200).
                    /readyz   — readiness (200 once feeds loaded + cache synced).
```

---

## Data flow — one report, end to end

```
 Trivy Operator creates / updates VulnerabilityReport
         │
         ▼
  Informer (client-go)                      Feed refresher (goroutine)
  detects Add/Update/Delete                 detects content change
         │                                         │
         ▼                                         ▼
  enqueue("namespace/name")          EnqueueAll() — every report key
         │                                         │
         └─────────────┬───────────────────────────┘
                       ▼
              Rate-limited workqueue
              (deduplicates keys)
                       │
                       ▼
              worker: process(key)
              ┌────────────────────────────────────┐
              │ 1. look up key in local cache       │
              │ 2. convert Unstructured → Report    │
              │ 3. resolve workload (RS→Deployment) │
              │ 4. enrich.Report(rep, w, epss, kev) │
              │    → []Series (deduped label-tuples)│
              │ 5. metrics.SetReport(key, series)   │
              │    → set gauges, delete stale ones  │
              └────────────────────────────────────┘
                       │
                       ▼
              /metrics (Prometheus scrape)
```

---

## Where to start reading

If you want to understand the **pure enrichment logic** (no dependencies):
→ `internal/enrich/enrich.go`

If you want to understand the **Kubernetes wiring** (informer + workqueue):
→ `internal/controller/controller.go`

If you want to understand **how the pieces are assembled**:
→ `internal/app/app.go`

If you want to understand **gauge lifecycle** (why we delete, not just set):
→ `internal/metrics/metrics.go`

The highest-value tests (no cluster needed) are in `internal/enrich/`,
`internal/epss/`, and `internal/kev/`.
