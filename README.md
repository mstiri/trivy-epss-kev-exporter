# trivy-epss-kev-exporter

[![ci](https://github.com/mstiri/trivy-epss-kev-exporter/actions/workflows/ci.yml/badge.svg)](https://github.com/mstiri/trivy-epss-kev-exporter/actions/workflows/ci.yml)
[![license](https://img.shields.io/github/license/mstiri/trivy-epss-kev-exporter)](https://github.com/mstiri/trivy-epss-kev-exporter/blob/main/LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/mstiri/trivy-epss-kev-exporter)](https://goreportcard.com/report/github.com/mstiri/trivy-epss-kev-exporter)

A read-only Prometheus exporter that turns [Trivy Operator](https://github.com/aquasecurity/trivy-operator)
`VulnerabilityReport` CVEs into **exploitability-aware** metrics — enriching each
CVE with its **EPSS score** (FIRST/EPSS) and **CISA KEV** presence, so you can
alert on what is *actually likely to be exploited* instead of raw CVSS counts.

It **writes nothing to the cluster** and **emits no alerts**: it only exposes
metrics. Alerting lives in your `PrometheusRule` / Alertmanager, keyed off the
metrics below.

## Why

A cluster scan can surface thousands of CVEs. Severity alone is a poor queue —
most CRITICALs are never exploited, and some are exploited *today*. EPSS gives a
daily exploitation-probability per CVE; CISA KEV lists CVEs known to be exploited
in the wild. Joining those onto your workloads lets you prioritize ruthlessly:
"KEV-listed, on an internet-facing Deployment" beats "CRITICAL, unscored."

## How it works

```
Trivy Operator ──(VulnerabilityReport CRDs)──▶ informer ──▶ enrich(CVE) ──▶ /metrics
                                                              ▲   ▲
                       EPSS bulk CSV ─(daily)─────────────────┘   │
                       CISA KEV JSON ─(daily)─────────────────────┘
```

Both feeds are bulk-loaded and cached in memory; every lookup is local (no
per-CVE API calls at scrape time). A change in a report *or* in a feed triggers
re-enrichment. See [`CLAUDE.md`](CLAUDE.md) for the full architecture and the
stable metric contract.

## Metrics

One series per `(cve × workload × container × resource)`:

| Metric | Type | Meaning |
|---|---|---|
| `trivy_vuln_epss_score` | gauge | EPSS exploitation probability `0.0–1.0` (`0` if the CVE is absent from the feed) |
| `trivy_vuln_epss_percentile` | gauge | EPSS percentile `0.0–1.0` |
| `trivy_vuln_kev` | gauge | `1` if the CVE is in the CISA KEV catalog, else `0` |
| `trivy_vuln_kev_ransomware` | gauge | `1` if the KEV entry is linked to a known ransomware campaign |

Labels: `cve`, `namespace`, `workload`, `workload_kind`, `container`,
`resource`, `severity`. Plus operability self-metrics
(`trivy_exporter_feed_last_success_timestamp_seconds`, `…_cache_synced`,
`…_build_info`, etc.).

### Example alerts (PromQL)

```promql
# A known-exploited (CISA KEV) CVE is present on a workload
trivy_vuln_kev == 1

# High predicted exploitation probability
trivy_vuln_epss_score > 0.5

# A feed has gone stale (no successful refresh in 36h)
time() - trivy_exporter_feed_last_success_timestamp_seconds > 36 * 3600
```

## Quick start

Requires a cluster running Trivy Operator (it produces the `VulnerabilityReport`
CRDs this exporter reads).

```sh
# Run locally against your kubeconfig:
go run ./cmd/trivy-epss-kev-exporter --kubeconfig ~/.kube/config
curl -s localhost:8080/metrics | grep trivy_vuln_

# Or the container image:
docker run --rm -p 8080:8080 -v ~/.kube/config:/kubeconfig:ro \
  ghcr.io/mstiri/trivy-epss-kev-exporter:latest --kubeconfig /kubeconfig
```

In-cluster, deploy with a single-replica `Deployment` + `ServiceMonitor` and a
**read-only** `ClusterRole` (`get/list/watch` on `vulnerabilityreports`, and
`replicasets` if workload roll-up is enabled). The exporter serves `/metrics`,
`/healthz`, and `/readyz` on port `8080`.

## Configuration

| Flag (env) | Default | Notes |
|---|---|---|
| `--epss-feed-url` (`EPSS_FEED_URL`) | `https://epss.empiricalsecurity.com/epss_scores-current.csv.gz` | gzipped CSV bulk feed |
| `--kev-feed-url` (`KEV_FEED_URL`) | `https://raw.githubusercontent.com/cisagov/kev-data/refs/heads/develop/known_exploited_vulnerabilities.json` | GitHub mirror of the CISA KEV catalog |
| `--feed-refresh-interval` | `24h` | both feeds recompute ~daily |
| `--feed-http-timeout` | `2m` | per-fetch HTTP timeout for feed downloads |
| `--namespaces` (`NAMESPACES`) | `` (empty) | comma-separated allowlist; empty = all namespaces. Does **not** accept `"all"` as a keyword |
| `--enable-rollup` | `true` | roll ReplicaSet workloads up to their owning Deployment (needs `replicasets` read RBAC) |
| `--enable-ransomware` | `true` | emit `trivy_vuln_kev_ransomware` gauge |
| `--metrics-port` / `--metrics-path` | `8080` / `/metrics` | also serves `/healthz` and `/readyz` |
| `--log-level` | `info` | `info`, `debug`, or `trace` |
| `--workers` | `2` | concurrent reconcile workers draining the workqueue |
| `--resync-interval` | `0` (off) | informer resync; not how feed changes are caught — leave at `0` |
| `--kubeconfig` | `` (empty) | path to kubeconfig; empty = in-cluster config |
| `--user-agent` | `trivy-epss-kev-exporter/<version> (+repo URL)` | User-Agent header sent on feed requests |

## Deployment notes

### ServiceMonitor: `honorLabels: true` is required

The exporter sets a `namespace` label on every vuln metric to identify the
**workload's** namespace (e.g. `litellm`, `kube-system`). Prometheus Operator
also injects a `namespace` label from the scrape target's namespace (typically
`trivy-system` where the exporter runs). Without `honorLabels: true`, Prometheus
overwrites the workload namespace with `trivy-system` on every series —
per-namespace breakdowns become impossible.


## Data sources

- **EPSS** — FIRST/EPSS daily bulk score feed.
- **CISA KEV** — Known Exploited Vulnerabilities catalog.

Both are cached in memory with graceful degradation (a failed refresh keeps the
last good data) and exposed freshness self-metrics.

## Contributing

Contributions are welcome! See [`CONTRIBUTING.md`](CONTRIBUTING.md). For a guided tour of the codebase
start with [`docs/architecture.md`](docs/architecture.md); the complete metrics
reference is in [`docs/metrics.md`](docs/metrics.md); the full design rationale
and stable metric contract are in [`CLAUDE.md`](CLAUDE.md).

## License

Apache-2.0.
