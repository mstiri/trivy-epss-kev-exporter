# Pre-production Validation Checklist

Run these checks against a staging or pre-prod cluster before promoting
to production. Suggested order: start with readiness and feed health (fast
feedback), then correctness, then lifecycle edge cases, then cardinality and
RBAC.

---

## 1. Readiness Gate

```sh
# Should return 503 immediately after pod start (feeds not yet loaded)
kubectl exec -n trivy-system deploy/trivy-epss-kev-exporter -- \
  wget -qO- http://localhost:8080/readyz

# Should return 200 once both feeds loaded + informer cache synced
kubectl exec -n trivy-system deploy/trivy-epss-kev-exporter -- \
  wget -qO- http://localhost:8080/healthz
```

- [x] `/readyz` returns 503 during startup, 200 once ready.
- [x] `/healthz` always returns 200.
- [x] Measure time from pod start to first 200 on `/readyz` — EPSS download + parse is the bottleneck; document the baseline.

Pod startup takes around 20s.

---

## 2. Feed Health

```promql
# Both feeds loaded recently
trivy_exporter_feed_last_success_timestamp_seconds

# No refresh failures
trivy_exporter_feed_refresh_failures_total

# Informer cache synced
trivy_exporter_cache_synced == 1
```

- [x] `feed_last_success_timestamp` is present for both `feed="epss"` and `feed="kev"`.
- [x] `feed_refresh_failures_total` is 0 for both.
- [x] `cache_synced == 1` within a few seconds of startup.
- [ ] After 24h+: confirm timestamps updated (daily refresh ran).

---

## 3. Metrics Presence & Correctness

Pick a known CVE from a `VulnerabilityReport` in the cluster.

```promql
# All three series should exist for every CVE
{__name__=~"trivy_vuln_.+", cve="CVE-2024-6345"}
```

Verify symmetry — all three queries should return **empty** (no missing series):

```promql
# epss_score without epss_percentile
trivy_vuln_epss_score unless on(cve,namespace,workload,workload_kind,container,resource,severity) trivy_vuln_epss_percentile

# epss_score without kev
trivy_vuln_epss_score unless on(cve,namespace,workload,workload_kind,container,resource,severity) trivy_vuln_kev

# kev without epss_score (reverse)
trivy_vuln_kev unless on(cve,namespace,workload,workload_kind,container,resource,severity) trivy_vuln_epss_score
```

Sanity-check totals — all three should match:

```promql
count(trivy_vuln_epss_score)
count(trivy_vuln_epss_percentile)
count(trivy_vuln_kev)
```

- [x] All three metrics (`epss_score`, `epss_percentile`, `kev`) are present for every CVE — no missing series.
- [ ] A CVE known to be in the CISA KEV catalog has `trivy_vuln_kev == 1`.
- [x] A CVE absent from the EPSS feed has `trivy_vuln_epss_score == 0` and `trivy_vuln_epss_percentile == 0` (series present, value 0 — not absent).
- [x] Cross-check one EPSS score against the raw feed value.
- [x] `severity` label matches the verbatim value from the `VulnerabilityReport` CRD (`CRITICAL`, `HIGH`, etc.) — not re-derived from CVSS.

---

## 4. Workload Roll-up

Find a report owned by a ReplicaSet (e.g. `replicaset-litellm-85bb58cf94-litellm`).

```promql
{__name__="trivy_vuln_kev", namespace="litellm"}
```

- [x] `workload` label shows the stable Deployment name (`litellm`), not the ReplicaSet hash (`litellm-85bb58cf94`).
- [x] `workload_kind` is `Deployment`.

---

## 5. Cardinality Check

```promql
# Total series count across all vuln metrics
count(trivy_vuln_epss_score)

# Per-namespace breakdown
count by (namespace) (trivy_vuln_epss_score)

# Per-workload (spot unexpected explosions)
count by (namespace, workload) (trivy_vuln_epss_score)
```

- [x] Total series count is in the thousands, not hundreds of thousands.
- [x] Sanity-check: `total ≈ unique (cve × workload × container × resource)` tuples.
- [x] No single workload dominates unexpectedly.

---

## 6. Memory & Resources

```sh
kubectl top pod -n trivy-system -l app.kubernetes.io/name=trivy-epss-kev-exporter
```

- [x] RSS is in the 30–80 MB range (EPSS map ~285k CVEs ≈ 30–50 MB + overhead).
- [ ] Memory is stable over time — the map is rebuilt on refresh, not appended.
- [x] Peak usage stays well under the 256 Mi limit.
- [x] Document the baseline RSS for future comparison.

RSS is arount 60MB all the time and stable.

---

## 7. Series Lifecycle — CRD Changes

### New report
- [x] Create a po and Confirm its CVEs appear in `/metrics` within a few seconds.

### Updated report (CVE fixed)
- [x] Update the test pod image tag.
  Confirm the stale series **disappears** (not just zeroed) within a few seconds.

### Deleted report
- [X] Delete the test pod.
  Confirm **all** series for that report are gone.

---

## 8. Series Lifecycle — Rollout (Reference Counting)

- [ ] Trigger a Deployment rollout:
  ```sh
  kubectl rollout restart deployment/<name> -n <ns>
  ```
- [ ] While two ReplicaSets coexist: confirm series are **not duplicated** — same `workload` label, same series count.
- [ ] After rollout completes (old RS deleted): series **survive** (still owned by new RS report).

---

## 9. Duplicate CVE Dedup

The Trivy Operator can emit the same CVE twice in one report (e.g. `CVE-2026-42561` appears twice in the sample CRD).

```promql
count by (cve, namespace, workload, container, resource) (trivy_vuln_epss_score)
```

- [x] No `(cve × workload × container × resource)` tuple has a count > 1.

**`cves_enriched_total`** is a cumulative counter — it grows with every reconcile, so its absolute value is not directly comparable to the series count. Check it two ways:

*Steady-state rate* — in steady state (no report changes, no feed refresh) this must be **0**:
```promql
rate(trivy_exporter_cves_enriched_total[5m])
```

*Post-restart increment* — right after the exporter starts (counter at 0) and before any feed refresh triggers a re-sweep, the total should equal `count(trivy_vuln_epss_score)`. A higher value means duplicates leaked through the dedup:
```promql
trivy_exporter_cves_enriched_total
count(trivy_vuln_epss_score)
```

- [x] Steady-state rate is 0.
- [x] Post-restart total ≈ `count(trivy_vuln_epss_score)`.

---

## 10. Feed Refresh Trigger (Trigger B)

To test without waiting 24h, temporarily set `--feed-refresh-interval=5m`.

### Unchanged content (no sweep)
- [ ] On a refresh that returns the same marker (`model_version`/`score_date` for EPSS, `catalogVersion`/`dateReleased` for KEV): confirm `trivy_exporter_reports_processed_total` does **not** spike.

### Changed content (sweep triggered)
- [ ] Simulate a feed change (e.g. swap to a different feed URL and back, or wait for a real daily update): confirm `reports_processed_total` increments for every report in the cluster.

---

## 11. RBAC — Least Privilege

```sh
SA="system:serviceaccount:trivy-system:trivy-epss-kev-exporter"

# Should be allowed
kubectl auth can-i list   vulnerabilityreports --as="$SA" -A
kubectl auth can-i get    vulnerabilityreports --as="$SA" -A
kubectl auth can-i watch  vulnerabilityreports --as="$SA" -A
kubectl auth can-i list   replicasets          --as="$SA" -A

# Should be denied
kubectl auth can-i create vulnerabilityreports --as="$SA" -A
kubectl auth can-i delete vulnerabilityreports --as="$SA" -A
kubectl auth can-i create pods                 --as="$SA" -A
kubectl auth can-i delete pods                 --as="$SA" -A
```

- [x] All `get/list/watch` on `vulnerabilityreports` and `replicasets` return **yes**.
- [x] All write verbs return **no**.

---

## 12. Build Info

```promql
trivy_exporter_build_info
```

- [x] `version`, `revision`, `branch`, and `goversion` labels are populated (not `dev`/`unknown`).
- [x] `revision` matches the Git SHA of the image that was built.

---

## Sign-off

| Area | Status | Notes |
|---|---|---|
| Readiness gate | | |
| Feed health | | |
| Metrics correctness | | |
| Workload roll-up | | |
| Cardinality | | |
| Memory & resources | | |
| Series lifecycle — CRD changes | | |
| Series lifecycle — rollout | | |
| Duplicate CVE dedup | | |
| Feed refresh trigger | | |
| RBAC | | |
| Build info | | |
