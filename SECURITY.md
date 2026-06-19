# Security Policy

## Reporting a vulnerability

Please report security vulnerabilities **privately** — do not open a public
issue for them.

Use GitHub's [private vulnerability reporting](https://github.com/mstiri/trivy-epss-kev-exporter/security/advisories/new)
("Report a vulnerability" under the repository's **Security** tab). This routes
the report directly to the maintainer and keeps the details confidential until a
fix is available.

When reporting, please include:

- A description of the issue and its potential impact.
- Steps to reproduce, or a proof of concept if you have one.
- The exporter version (`trivy_exporter_build_info`) and how it is deployed.

You can expect an initial acknowledgement within a few days. Once the issue is
confirmed, a fix and a coordinated disclosure timeline will be agreed with you.

## Scope

This is a **read-only** Prometheus exporter. It holds no credentials beyond the
read-only Kubernetes ServiceAccount token mounted by the cluster, performs no
writes to the cluster, and exposes only an HTTP metrics/health endpoint plus
outbound HTTPS fetches to the configured EPSS and KEV feeds. Reports that are
especially relevant:

- Anything that could turn the exporter's cluster read access into a write or
  escalation path.
- Exposure of sensitive data through the `/metrics`, `/healthz`, or `/readyz`
  endpoints.
- Issues in how the external feeds are fetched or parsed (e.g. a malicious feed
  response causing unsafe behavior).
