# Metrics reference

Complete inventory of every metric this exporter emits, with labels, semantics,
and alerting guidance.

---

## Vulnerability metrics

One series per unique `(cve × namespace × workload × container × resource)`
tuple. Every tuple always carries all three core metrics — they are always
symmetric (see [Symmetry guarantee](#symmetry-guarantee)).

### `trivy_vuln_epss_score`

| | |
|---|---|
| **Type** | Gauge |
| **Value range** | `0.0 – 1.0` |
| **Labels** | `cve`, `namespace`, `workload`, `workload_kind`, `container`, `resource`, `severity` |

EPSS exploitation probability for this CVE. Sourced daily from the FIRST/EPSS
bulk feed.

- A value of `0` means the CVE is **not in the EPSS feed** (not scored), not
  that its probability is zero. Real EPSS scores are never exactly `0.0` (feed
  minimum is ~`1e-5`).
- Updated daily when the feed refreshes and content has changed.

**Alert example:**
```promql
trivy_vuln_epss_score > 0.5
```

---

### `trivy_vuln_epss_percentile`

| | |
|---|---|
| **Type** | Gauge |
| **Value range** | `0.0 – 1.0` |
| **Labels** | `cve`, `namespace`, `workload`, `workload_kind`, `container`, `resource`, `severity` |

EPSS percentile — how this CVE ranks relative to all other scored CVEs. A
percentile of `0.95` means this CVE is in the top 5% by predicted exploitation
probability.

- `0` means not in the EPSS feed (same semantics as `epss_score`).
- Useful for relative prioritization when the raw score feels arbitrary.

**Alert example:**
```promql
trivy_vuln_epss_percentile > 0.95
```

---

### `trivy_vuln_kev`

| | |
|---|---|
| **Type** | Gauge |
| **Value** | `1` if in the CISA KEV catalog, `0` otherwise |
| **Labels** | `cve`, `namespace`, `workload`, `workload_kind`, `container`, `resource`, `severity` |

Whether the CVE appears in the [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
catalog. A value of `1` means the vulnerability is confirmed to have been
exploited in the wild.

**Alert example:**
```promql
trivy_vuln_kev == 1
```

---

### `trivy_vuln_kev_ransomware`

| | |
|---|---|
| **Type** | Gauge |
| **Value** | `1` if linked to a known ransomware campaign, `0` otherwise |
| **Labels** | `cve`, `namespace`, `workload`, `workload_kind`, `container`, `resource`, `severity` |
| **Emitted when** | `--enable-ransomware=true` (default) |

Whether the CVE's KEV entry has `knownRansomwareCampaignUse == "Known"`. A
subset of `trivy_vuln_kev == 1` — every ransomware-linked CVE is also in the
KEV catalog, but not vice versa.

**Alert example:**
```promql
trivy_vuln_kev_ransomware == 1
```

---

### Labels

| Label | Example | Source |
|---|---|---|
| `cve` | `CVE-2021-44228` | `vulnerabilityID` field in the CRD |
| `namespace` | `litellm` | `trivy-operator.resource.namespace` label on the report |
| `workload` | `litellm` | Resolved from `trivy-operator.resource.name`, rolled up from ReplicaSet to Deployment |
| `workload_kind` | `Deployment` | Resolved from `trivy-operator.resource.kind`, rolled up |
| `container` | `litellm` | `trivy-operator.container.name` label on the report |
| `resource` | `log4j-core` | `resource` field in the CRD vulnerability entry |
| `severity` | `HIGH` | `severity` field verbatim from the CRD — NOT re-derived from CVSS |

### Symmetry guarantee

Every `(cve × namespace × workload × container × resource)` tuple always has
all three core gauges (`epss_score`, `epss_percentile`, `kev`) present — none
is ever omitted. This means PromQL joins across the three metrics never drop
rows. `kev_ransomware` follows the same rule when enabled.

Verify with (all should return empty):
```promql
trivy_vuln_epss_score unless on(cve,namespace,workload,workload_kind,container,resource,severity) trivy_vuln_epss_percentile
trivy_vuln_epss_score unless on(cve,namespace,workload,workload_kind,container,resource,severity) trivy_vuln_kev
```

---

## Self / operability metrics

These metrics describe the health of the exporter itself. Use them to alert on
stale data or loss of cluster visibility independently of the vulnerability
metrics.

---

### `trivy_exporter_feed_last_success_timestamp_seconds`

| | |
|---|---|
| **Type** | Gauge |
| **Value** | Unix timestamp (seconds) of the last successful feed refresh |
| **Labels** | `feed` — `"epss"` or `"kev"` |

Updated on every successful feed download, regardless of whether content
changed. Use `time() - trivy_exporter_feed_last_success_timestamp_seconds` to
compute staleness.

**Alert example** (no successful refresh in 36 hours):
```promql
time() - trivy_exporter_feed_last_success_timestamp_seconds{feed="epss"} > 36 * 3600
time() - trivy_exporter_feed_last_success_timestamp_seconds{feed="kev"}  > 36 * 3600
```

---

### `trivy_exporter_feed_refresh_failures_total`

| | |
|---|---|
| **Type** | Counter |
| **Labels** | `feed` — `"epss"` or `"kev"` |

Incremented on every failed feed refresh attempt (network error, non-200
status, parse error). The last good snapshot continues serving on failure.

**Alert example** (any failure in the last hour):
```promql
increase(trivy_exporter_feed_refresh_failures_total[1h]) > 0
```

---

### `trivy_exporter_cache_synced`

| | |
|---|---|
| **Type** | Gauge |
| **Value** | `1` once the informer cache has synced, `0` otherwise |
| **Labels** | none |

Set to `1` once the initial List of all `VulnerabilityReport` objects from the
API server is complete and the local cache is warm. Before this point, the
exporter has no vulnerability data to enrich. The `/readyz` endpoint also gates
on this.

**Alert example** (cache not synced 5 minutes after start):
```promql
trivy_exporter_cache_synced == 0
```

---

### `trivy_exporter_reports_processed_total`

| | |
|---|---|
| **Type** | Counter |
| **Labels** | none |

Incremented once per `VulnerabilityReport` reconcile pass (whether triggered by
a CRD event or a feed change sweep). In steady state (no changes) this counter
does not move. A sudden large spike indicates a feed content change triggered a
full re-sweep of all reports.

---

### `trivy_exporter_cves_enriched_total`

| | |
|---|---|
| **Type** | Counter |
| **Labels** | none |

Incremented by the number of unique CVE series set in each reconcile pass.
In steady state the rate should be `0`. Use to detect unexpected re-enrichment
loops:

```promql
rate(trivy_exporter_cves_enriched_total[5m]) > 0
```

Right after startup (counter at `0`), before the first feed refresh sweep, this
total should equal `count(trivy_vuln_epss_score)` — one increment per unique
label tuple from the initial reconcile of all reports.

---

### `trivy_exporter_build_info`

| | |
|---|---|
| **Type** | Gauge (always `1`) |
| **Labels** | `version`, `revision`, `branch`, `goversion` |

Build provenance. Stamped at link time via `-ldflags` in the Dockerfile.
Useful for confirming which image version is running:

```promql
trivy_exporter_build_info
```

---

## Standard Go / process metrics

The exporter also exposes the standard `prometheus/client_golang` collectors:

| Prefix | Description |
|---|---|
| `go_*` | Go runtime metrics (GC, goroutines, memory) |
| `process_*` | Process metrics (CPU, memory, file descriptors) |

These are useful for diagnosing memory growth or GC pressure after a feed
refresh that rebuilds the EPSS map (~285k entries).
