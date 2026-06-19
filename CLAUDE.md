# CLAUDE.md — trivy-epss-kev-exporter

## What this project is

A **read-only Prometheus exporter** written in Go. It watches Trivy Operator
`VulnerabilityReport` CRDs via an informer, enriches each CVE with its **EPSS
score** (FIRST/EPSS bulk CSV feed) and **CISA KEV presence** (KEV JSON feed),
and exposes the result as Prometheus metrics on `/metrics`.

It **writes nothing to the cluster** and **emits no alerts**. Alerting policy
lives entirely in `PrometheusRule` / Alertmanager and keys off the metrics this
exporter produces. This is an exporter, **not an operator** — there is no
reconciliation, no CRDs of our own, no write access of any kind.

---

## Non-goals (do not build these)

- No alerting / notification logic. We only expose metrics.
- No writes to the cluster (no create/update/delete, no CRDs, no webhooks,
  no finalizers).
- No per-CVE calls to external APIs at scrape time. Feeds are bulk-loaded and
  cached; lookups are local.
- We do NOT rely on the operator's `metricsVulnIdEnabled` flag. We read CRDs.

---

## Architecture

There is **one idempotent operation** — `enrich(report)` — driven by **two
independent triggers**. Do not collapse these onto a single clock.

```
DynamicSharedInformerFactory (VulnerabilityReport CRDs)
   ├─ warm in-memory cache  ← Indexer reads from here
   └─ event handlers (OnAdd / OnUpdate / OnDelete)
   (Dynamic because VulnerabilityReport is a CRD with no generated Go type;
    objects arrive as *unstructured.Unstructured and are converted locally)

TRIGGER A — a CRD changed (report created/updated/deleted by the operator)
   OnAdd / OnUpdate(report) → enqueue(report key)
   OnDelete(report)         → enqueue(report key, as delete)

TRIGGER B — a FEED changed (EPSS recomputed, or KEV gained/flagged a CVE)
   feed refresher detects content changed (NOT just "refresh ran")
        → sweep: enqueue EVERY report key from the Lister

Single workqueue  →  worker pops key  →  enrich(report)  →  reconcile gauges
                                          (or delete series if report gone)

Feed refreshers (separate goroutines, timer-driven):
   EPSS CSV  → in-memory map[cve]→{score, percentile}   (refresh ~daily)
   KEV  JSON → in-memory set[cve] (+ optional ransomware flag) (refresh ~daily)
```

### Why two triggers (and not resync)

- **Informer events** know about CRD changes, NOT feed changes. They re-enrich
  the one report that changed. Correct trigger for that case.
- **Feed changes** alter the enrichment output for potentially every report,
  but no CRD changed, so the informer never fires. The feed refresher must
  trigger the re-enrichment itself by sweeping the Lister.
- Therefore **informer resync is NOT our mechanism for feed updates.** You may
  set a long resync or disable it; its only legitimate role here is minor
  self-healing of derived state, which we get anyway by recomputing gauges from
  scratch. Do not use resync as a proxy for "EPSS might have changed."

### Feed change detection (don't sweep on every refresh)

Only run the Trigger-B sweep when feed CONTENT actually changed — otherwise a
daily refresh that returns identical data needlessly re-enriches everything.

- **EPSS**: the CSV preamble carries `model_version` / `score_date`. Unchanged
  marker ⇒ unchanged data ⇒ skip sweep.
- **KEV**: the JSON has `catalogVersion` / `dateReleased` at the top. Same idea.
- Fallback: hash the raw payload and compare.

On a successful-but-unchanged refresh, still update
`trivy_exporter_feed_last_success_timestamp_seconds`; just don't sweep.

### Series lifecycle — enrich() must REPLACE, not just upsert

A report's CVE set can SHRINK (a vuln gets fixed). If you only `Set()` gauges,
stale series for removed CVEs linger forever. So:

- Track which series belong to each report: `map[reportUID] → set of label-tuples`.
- On re-enrich: compute the new series set, set those, and **delete** any series
  for that report no longer present.
- On `OnDelete(report)`: delete ALL series for that report UID.
- **Reference-count series across reports.** With Deployment roll-up (above), two
  reports can legitimately own the SAME label-tuple. A flat per-UID delete would
  yank a series another report still needs. So keep `map[label-tuple] → refcount`
  alongside the per-UID set: a tuple's gauge is deleted only when its refcount
  hits 0. (Values stay consistent because the same tuple ⇒ same CVE ⇒ same
  enrichment, so whichever report writes last writes the same number.)
- **De-dup within a report.** The operator can emit the SAME vuln twice (identical
  `cve` + `resource` + container — see the sample CRD: `CVE-2026-42561`,
  `CVE-2026-44431`, `CVE-2026-44432` each appear twice). Because the per-report
  state is a *set* of label-tuples, this collapses to one series naturally (same
  enrichment, last-write-wins). Build the new series set as a **set, not a slice**
  so duplicates can't create churn or double-count `cves_enriched_total`.

This per-report series map is the only state we keep — it is bookkeeping, not
alert state.

### Concurrency

Trigger A and Trigger B can fire concurrently and both touch the metrics
registry + the per-report series map. **Funnel both through the single
workqueue** so enrichment is serialized per report key — this also gives free
dedup (a key enqueued twice is processed once). This is the one place the
classic controller workqueue pattern genuinely earns its keep in this otherwise
simple exporter.

### Library choice — client-go (decided)

Use **raw client-go**, not controller-runtime. This is a **single-replica**,
read-only, stateless exporter: fast restart recovery, non-time-critical data, no
HA requirement. Leader election / multi-replica headroom isn't worth the
duplicate-series complexity, and controller-runtime's modern default of serving
`/metrics` over HTTPS-with-authn would fight a plain `ServiceMonitor` scrape.

Concretely:
- `DynamicSharedInformerFactory` for the `VulnerabilityReport` watch → warm
  cache + Indexer. Dynamic because VulnerabilityReport is a CRD with no
  generated Go type; a typed `SharedInformerFactory` is used separately for
  ReplicaSets (built-in type, needed for RS→Deployment roll-up).
- `client-go/util/workqueue` (rate-limited) for the single workqueue both
  triggers funnel through.
- A small `net/http` server **we own** for `/metrics`, `/healthz`, `/readyz`.

**Document the informer machinery in comments** — list-then-watch, the
cache/store, event handlers (OnAdd/OnUpdate/OnDelete), `WaitForCacheSync`, and
resync — so the abstraction is explicit for future readers.

---

## Metric contract (STABLE — changing this breaks alerting rules)

Two gauges, one series per (CVE × workload × container × resource):

| Metric | Type | Meaning |
|---|---|---|
| `trivy_vuln_epss_score` | gauge | EPSS probability `0.0–1.0` (the raw float, as a VALUE) |
| `trivy_vuln_epss_percentile` | gauge | EPSS percentile `0.0–1.0` |
| `trivy_vuln_kev` | gauge | `1` if CVE is in the CISA KEV catalog, else `0` |
| `trivy_vuln_kev_ransomware` | gauge | `1` if KEV `knownRansomwareCampaignUse == "Known"`. Optional (decide during build) |

### Missing-data semantics (EPSS absent)

A CVE may be present in a report but absent from the EPSS feed. In that case
**emit `trivy_vuln_epss_score` and `trivy_vuln_epss_percentile` with value `0`**
(do NOT omit the series). Rationale:

- Threshold alerts (`epss_score > X`, `epss_percentile > X`) then simply never
  fire for unscored CVEs — the desired behavior.
- The three gauges (`epss_score`, `epss_percentile`, `kev`) stay **symmetric** —
  every `(cve × workload × container × resource)` tuple always carries all three —
  so PromQL joins never drop rows.
- Real EPSS scores are never exactly `0.0` (feed minimum is ~`1e-5`), so a `0`
  unambiguously reads as "no EPSS data" without a separate sentinel.

`trivy_vuln_kev` is `0`/`1` by definition (`0` = not in the KEV catalog), so it
is always emitted regardless of EPSS coverage.

### Labels (KEEP LEAN — cardinality discipline)

```
cve              e.g. CVE-2021-44228
namespace        workload namespace
workload         owner workload name (from ownerReferences / operator labels)
workload_kind    Deployment | StatefulSet | DaemonSet | ...
container        container name
resource         affected package/resource (e.g. log4j-core)
severity         CRITICAL | HIGH | MEDIUM | LOW | UNKNOWN
                 (taken verbatim from the CRD vuln's `severity` field —
                  NOT re-derived from the CVSS `score`)
```

### Cardinality rules (HARD)

- **Raw EPSS float is a VALUE, never a label.** It changes daily; as a label it
  would churn series endlessly.
- **Do NOT** put as labels: EPSS score, image digest, installed/fixed version,
  CVE description, primary link, timestamps.
- KEV is low-cardinality (`1`/`0`) → fine as a value.
- If a label set risks blowing up on a large cluster, raise it with me before
  adding the label. Lean beats complete.

---

## Data sources

### EPSS
- Use the **bulk gzipped CSV** feed, NOT the per-CVE API.
- URL (configurable): `https://epss.empiricalsecurity.com/epss_scores-current.csv.gz`
  (confirm/override at build time — feed host has moved historically).
- Parse into `map[string]struct{ Score, Percentile float64 }` keyed by CVE ID.
- Refresh on a timer (default daily; EPSS recomputes once per day).

### CISA KEV
- URL (configurable):
  `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
- Parse into `map[string]bool` (presence) plus optional ransomware flag from
  the `knownRansomwareCampaignUse` field (`"Known"` vs `"Unknown"`).
- Refresh on a timer (default daily).

### Feed handling requirements
- Both feeds cached in memory; all enrichment is a local map/set lookup.
- **Graceful degradation:** if a refresh fails, keep serving the last good data.
- Expose freshness as self-metrics (see below) so staleness is alertable.

---

## Source-of-truth CRD

Group/Version/Kind: `aquasecurity.github.io/v1alpha1`, `VulnerabilityReport`.

Workload ownership is derived from `ownerReferences` and/or the operator's
labels on the report:
- `trivy-operator.resource.kind`
- `trivy-operator.resource.name`
- `trivy-operator.resource.namespace`
- `trivy-operator.container.name`

**Workload roll-up (decided — implement in step 5).** The operator labels point
at the IMMEDIATELY scanned resource, which for a Deployment is the *ReplicaSet*
(e.g. kind=`ReplicaSet`, name=`litellm-85bb58cf94`). We roll that **up to the
owning Deployment** so the `workload` label is the stable Deployment name
(`litellm`), not a per-rollout RS hash. This needs a **ReplicaSet lister**
(read RBAC on `replicasets`) to read the RS's own `ownerReferences`. The pure
`enrich` core stays unchanged — roll-up happens in workload resolution, behind an
injectable resolver (identity in unit tests, lister-backed at runtime).

Consequence for the series map (below): two reports — the old RS and the new RS
during a rollout — both roll up to the SAME `workload`, so they can contribute
the **same label-tuple**. Series ownership is therefore **reference-counted**, not
a flat per-UID delete, so deleting one report doesn't drop a series another
report still owns.


### Real CRD sample of a VulnerabilityReport

A real `kubectl get vulnerabilityreport <name> -n <ns> -o yaml` from the
target cluster is below.

```yaml
apiVersion: aquasecurity.github.io/v1alpha1
kind: VulnerabilityReport
metadata:
  annotations:
    trivy-operator.aquasecurity.github.io/report-ttl: 168h0m0s
  labels:
    app.kubernetes.io/managed-by: trivy-operator
    resource-spec-hash: 8699667f94
    trivy-operator.container.name: litellm
    trivy-operator.resource.kind: ReplicaSet
    trivy-operator.resource.name: litellm-85bb58cf94
    trivy-operator.resource.namespace: litellm
  name: replicaset-litellm-85bb58cf94-litellm
  namespace: litellm
  ownerReferences:
  - apiVersion: apps/v1
    blockOwnerDeletion: false
    controller: true
    kind: ReplicaSet
    name: litellm-85bb58cf94
    uid: 312c846f-0679-40b0-bcf9-418b33ce9170
  resourceVersion: "35775475"
  uid: 0b80c1d9-52cd-4715-9d2f-41967cee6c17
report:
  artifact:
    digest: sha256:ec721a5e4b0decb3658c74b696e315dc3e1c664adbfbadded0564ee2d6cc03bc
    repository: berriai/litellm-database
    tag: main-v1.83.14-stable.patch.3
  os:
    family: wolfi
    name: "20230201"
  registry:
    server: ghcr.io
  scanner:
    name: Trivy
    vendor: Aqua Security
    version: 0.69.3
  summary:
    criticalCount: 0
    highCount: 13
    lowCount: 0
    mediumCount: 0
    noneCount: 0
    unknownCount: 0
  vulnerabilities:
  - fixedVersion: 1.37.0-r58
    installedVersion: 1.37.0-r57
    lastModifiedDate: "2025-04-24T20:15:31Z"
    links: []
    packagePURL: pkg:apk/wolfi/busybox@1.37.0-r57?arch=x86_64&distro=20230201
    primaryLink: https://avd.aquasec.com/nvd/cve-2023-39810
    publishedDate: "2023-08-28T19:15:07Z"
    resource: busybox
    score: 7.3
    severity: HIGH
    target: ""
    title: 'busybox: CPIO command of Busybox allows attackers to execute a directory
      traversal'
    vulnerabilityID: CVE-2023-39810
  - fixedVersion: 26.1.1-r0
    installedVersion: 26.0.1-r2
    lastModifiedDate: "2025-12-10T16:08:32Z"
    links: []
    packagePURL: pkg:apk/wolfi/py3-pip-wheel@26.0.1-r2?arch=x86_64&distro=20230201
    primaryLink: https://avd.aquasec.com/nvd/cve-2025-66418
    publishedDate: "2025-12-05T16:15:51Z"
    resource: py3-pip-wheel
    score: 7.5
    severity: HIGH
    target: ""
    title: 'urllib3: urllib3: Unbounded decompression chain leads to resource exhaustion'
    vulnerabilityID: CVE-2025-66418
  - fixedVersion: 26.1.1-r0
    installedVersion: 26.0.1-r2
    lastModifiedDate: "2025-12-10T16:10:33Z"
    links: []
    packagePURL: pkg:apk/wolfi/py3-pip-wheel@26.0.1-r2?arch=x86_64&distro=20230201
    primaryLink: https://avd.aquasec.com/nvd/cve-2025-66471
    publishedDate: "2025-12-05T17:16:04Z"
    resource: py3-pip-wheel
    score: 7.5
    severity: HIGH
    target: ""
    title: 'urllib3: urllib3 Streaming API improperly handles highly compressed data'
    vulnerabilityID: CVE-2025-66471
  - fixedVersion: 26.1.1-r0
    installedVersion: 26.0.1-r2
    lastModifiedDate: "2026-01-23T09:15:47Z"
    links: []
    packagePURL: pkg:apk/wolfi/py3-pip-wheel@26.0.1-r2?arch=x86_64&distro=20230201
    primaryLink: https://avd.aquasec.com/nvd/cve-2026-21441
    publishedDate: "2026-01-07T22:15:44Z"
    resource: py3-pip-wheel
    score: 7.5
    severity: HIGH
    target: ""
    title: 'urllib3: urllib3 vulnerable to decompression-bomb safeguard bypass when
      following HTTP redirects (streaming API)'
    vulnerabilityID: CVE-2026-21441
  - fixedVersion: 4.0.4, 3.0.2, 2.3.2
    installedVersion: 4.0.3
    lastModifiedDate: "2026-04-01T13:45:11Z"
    links: []
    packagePURL: pkg:npm/picomatch@4.0.3
    primaryLink: https://avd.aquasec.com/nvd/cve-2026-33671
    publishedDate: "2026-03-26T22:16:30Z"
    resource: picomatch
    score: 6.5
    severity: HIGH
    target: ""
    title: 'picomatch: Picomatch: Regular Expression Denial of Service via crafted
      extglob patterns'
    vulnerabilityID: CVE-2026-33671
  - fixedVersion: 0.0.27
    installedVersion: 0.0.26
    lastModifiedDate: "2026-05-14T17:00:31Z"
    links: []
    packagePURL: pkg:pypi/python-multipart@0.0.26
    primaryLink: https://avd.aquasec.com/nvd/cve-2026-42561
    publishedDate: "2026-05-13T21:16:47Z"
    resource: python-multipart
    score: 7.5
    severity: HIGH
    target: ""
    title: Python-Multipart is a streaming multipart parser for Python. Prior to  ...
    vulnerabilityID: CVE-2026-42561
  - fixedVersion: 0.0.27
    installedVersion: 0.0.26
    lastModifiedDate: "2026-05-14T17:00:31Z"
    links: []
    packagePURL: pkg:pypi/python-multipart@0.0.26
    primaryLink: https://avd.aquasec.com/nvd/cve-2026-42561
    publishedDate: "2026-05-13T21:16:47Z"
    resource: python-multipart
    score: 7.5
    severity: HIGH
    target: ""
    title: Python-Multipart is a streaming multipart parser for Python. Prior to  ...
    vulnerabilityID: CVE-2026-42561
  - fixedVersion: 70.0.0
    installedVersion: 68.1.2
    lastModifiedDate: "2026-04-15T00:35:42Z"
    links: []
    packagePURL: pkg:pypi/setuptools@68.1.2
    primaryLink: https://avd.aquasec.com/nvd/cve-2024-6345
    publishedDate: "2024-07-15T01:15:01Z"
    resource: setuptools
    score: 8.8
    severity: HIGH
    target: ""
    title: 'pypa/setuptools: Remote code execution via download functions in the package_index
      module in pypa/setuptools'
    vulnerabilityID: CVE-2024-6345
  - fixedVersion: 78.1.1
    installedVersion: 68.1.2
    lastModifiedDate: "2025-06-12T16:29:01Z"
    links: []
    packagePURL: pkg:pypi/setuptools@68.1.2
    primaryLink: https://avd.aquasec.com/nvd/cve-2025-47273
    publishedDate: "2025-05-17T16:15:19Z"
    resource: setuptools
    score: 7.1
    severity: HIGH
    target: ""
    title: 'setuptools: Path Traversal Vulnerability in setuptools PackageIndex'
    vulnerabilityID: CVE-2025-47273
  - fixedVersion: 2.7.0
    installedVersion: 2.6.3
    lastModifiedDate: "2026-05-14T13:56:27Z"
    links: []
    packagePURL: pkg:pypi/urllib3@2.6.3
    primaryLink: https://avd.aquasec.com/nvd/cve-2026-44431
    publishedDate: "2026-05-13T16:16:57Z"
    resource: urllib3
    score: 5.3
    severity: HIGH
    target: ""
    title: 'urllib3: urllib3: Information disclosure via cross-origin redirects forwarding
      sensitive headers'
    vulnerabilityID: CVE-2026-44431
  - fixedVersion: 2.7.0
    installedVersion: 2.6.3
    lastModifiedDate: "2026-05-14T13:56:27Z"
    links: []
    packagePURL: pkg:pypi/urllib3@2.6.3
    primaryLink: https://avd.aquasec.com/nvd/cve-2026-44431
    publishedDate: "2026-05-13T16:16:57Z"
    resource: urllib3
    score: 5.3
    severity: HIGH
    target: ""
    title: 'urllib3: urllib3: Information disclosure via cross-origin redirects forwarding
      sensitive headers'
    vulnerabilityID: CVE-2026-44431
  - fixedVersion: 2.7.0
    installedVersion: 2.6.3
    lastModifiedDate: "2026-05-14T13:49:25Z"
    links: []
    packagePURL: pkg:pypi/urllib3@2.6.3
    primaryLink: https://avd.aquasec.com/nvd/cve-2026-44432
    publishedDate: "2026-05-13T16:16:57Z"
    resource: urllib3
    score: 7.5
    severity: HIGH
    target: ""
    title: 'urllib3: urllib3: Denial of Service due to excessive HTTP response decompression'
    vulnerabilityID: CVE-2026-44432
  - fixedVersion: 2.7.0
    installedVersion: 2.6.3
    lastModifiedDate: "2026-05-14T13:49:25Z"
    links: []
    packagePURL: pkg:pypi/urllib3@2.6.3
    primaryLink: https://avd.aquasec.com/nvd/cve-2026-44432
    publishedDate: "2026-05-13T16:16:57Z"
    resource: urllib3
    score: 7.5
    severity: HIGH
    target: ""
    title: 'urllib3: urllib3: Denial of Service due to excessive HTTP response decompression'
    vulnerabilityID: CVE-2026-44432
```

---

## Self-metrics (operability)

```
trivy_exporter_feed_last_success_timestamp_seconds{feed="epss|kev"}  gauge (unix secs)
trivy_exporter_feed_refresh_failures_total{feed="epss|kev"}  counter
trivy_exporter_reports_processed_total                       counter
trivy_exporter_cves_enriched_total                           counter
trivy_exporter_cache_synced                                  gauge (1 once informer synced)
trivy_exporter_build_info{version,revision,branch,goversion} gauge (=1; build provenance)
```

These let us alert on stale feeds / desync independently of the vuln metrics.

---

## Configuration (flags + env)

- `--epss-feed-url`         (env `EPSS_FEED_URL`)
- `--kev-feed-url`          (env `KEV_FEED_URL`)
- `--feed-refresh-interval` default `24h` — drives the Trigger-B feed refresh
  (both feeds recompute ~once/day)
- `--resync-interval`       default `0` (disabled). Informer resync is NOT how we
  catch feed changes (see Architecture). Set non-zero only if you want periodic
  self-healing of derived state; not required.
- `--metrics-port`          default `8080`
- `--metrics-path`          default `/metrics`
- `--log-level`             default `info`
- `--namespaces`            optional allowlist; empty = all namespaces
- `--kubeconfig`            optional; empty = in-cluster config (for local/dev runs)

---

## Deliverables / artifacts

- Go module `github.com/mstiri/trivy-epss-kev-exporter`, single static binary.
- **Dockerfile**: multi-stage build, **distroless or scratch** final image,
  non-root.
- **Kubernetes manifests**:
  - `Deployment` (single replica, non-root, read-only root FS, minimal resources;
    note the EPSS map holds ~285k CVEs ≈ 30–50 MB resident — size requests/limits
    accordingly, this is not a "few MB" workload)
  - `Service` (exposes metrics port)
  - `ServiceMonitor` (Prometheus Operator) — or `PodMonitor` if simpler
  - **RBAC**: `ServiceAccount` + `ClusterRole` + `ClusterRoleBinding` with
    **read-only** verbs `get/list/watch` on `vulnerabilityreports`
    (and `replicasets`/`deployments` ONLY if needed to resolve ownership).
    **No write verbs anywhere.**
- `/healthz` (liveness) and `/readyz` (readiness gated on: informer cache
  synced AND both feeds loaded at least once).

---

## Working style for Claude Code

- **Build incrementally; let me review at each step.** Suggested order:
  1. EPSS CSV loader + parser (pure, unit-tested)
  2. KEV JSON loader + parser (pure, unit-tested)
  3. Enrichment function: `(cve) -> {epss, kev}` (pure, unit-tested)
  4. Prometheus metric registration + gauge wiring
  5. client-go DynamicSharedInformerFactory + indexer + workqueue (CRD watch)
  6. Glue: handler/resync → enrich → set gauges
  7. HTTP server (`/metrics`, `/healthz`, `/readyz`) + self-metrics
  8. Dockerfile + manifests + RBAC
- **Unit-test the pure parts** (feed parsing, enrichment) thoroughly — these are
  the highest-value tests and don't need a cluster.
- Keep this `CLAUDE.md` updated as the source of truth for the metric contract
  and architecture. If a design decision changes, change it here too.
- When in doubt about a CRD field path, STOP and ask — don't guess (see the
  placeholder above).