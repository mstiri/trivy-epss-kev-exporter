# Deploying trivy-epss-kev-exporter

Read-only Prometheus exporter that enriches Trivy Operator `VulnerabilityReport`
CVEs with EPSS scores and CISA KEV presence. See `../CLAUDE.md` for the metric
contract and architecture.

## Prerequisites

- A cluster running **Trivy Operator** (produces the `VulnerabilityReport` CRDs).
- The `trivy-system` namespace (adjust the manifests if you deploy elsewhere).
- Optional: **Prometheus Operator** for the `ServiceMonitor` (otherwise scrape
  the `Service` however you normally do).
- Outbound HTTPS egress to the EPSS and KEV feed hosts.

## Deploy

```sh
# Kustomize (set the image tag in kustomization.yaml or with `kustomize edit`):
kubectl apply -k deploy/

# …or plain manifests:
kubectl apply -f deploy/rbac.yaml -f deploy/deployment.yaml \
              -f deploy/service.yaml -f deploy/servicemonitor.yaml
```

`example-prometheusrule.yaml` is a **sample** alert set (KEV present, EPSS/percentile
thresholds, feed-staleness) — not applied by kustomize. Tune and apply separately.

## Verify

```sh
kubectl -n trivy-system rollout status deploy/trivy-epss-kev-exporter
kubectl -n trivy-system port-forward deploy/trivy-epss-kev-exporter 8080:8080 &

curl -s localhost:8080/readyz                      # "ready" once synced + feeds loaded
curl -s localhost:8080/metrics | grep trivy_vuln_  # enriched series
```

## Configuration (flags / env)

| Flag (env) | Default | Notes |
|---|---|---|
| `--epss-feed-url` (`EPSS_FEED_URL`) | `https://epss.empiricalsecurity.com/epss_scores-current.csv.gz` | gzipped CSV bulk feed |
| `--kev-feed-url` (`KEV_FEED_URL`) | `https://raw.githubusercontent.com/cisagov/kev-data/refs/heads/develop/known_exploited_vulnerabilities.json` | GitHub mirror of the CISA KEV catalog |
| `--feed-refresh-interval` | `24h` | both feeds recompute ~daily |
| `--resync-interval` | `0` (off) | not how feed changes are caught; leave at 0 |
| `--metrics-port` / `--metrics-path` | `8080` / `/metrics` | also serves `/healthz`, `/readyz` |
| `--namespaces` (`NAMESPACES`) | `` (empty) | comma-separated allowlist; empty = all namespaces. Does **not** accept `"all"` as a keyword |
| `--kubeconfig` | `` (empty) | path to kubeconfig; empty = in-cluster config |
| `--enable-rollup` | `true` | roll ReplicaSet→Deployment `workload` label (needs `replicasets` read RBAC) |
| `--enable-ransomware` | `true` | emit `trivy_vuln_kev_ransomware` gauge |
| `--log-level` | `info` | `info\|debug\|trace` |

## RBAC

`get/list/watch` on `vulnerabilityreports` and `replicasets` only — **no write
verbs**. Drop the `replicasets` rule if you run with `--enable-rollup=false`.
