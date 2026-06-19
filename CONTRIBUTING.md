# Contributing to trivy-epss-kev-exporter

Thanks for your interest in contributing! This project is a small, read-only
Prometheus exporter, and we aim to keep it that way — lean, well-tested, and
easy to reason about. Issues, ideas, and pull requests are all welcome.

Please read [`CLAUDE.md`](CLAUDE.md) first: it is the source of truth for the
architecture, the **stable metric contract**, and the design decisions (e.g. why
we use raw client-go, the two-trigger model, and the series lifecycle). Changes
that affect the metric contract or labels need a discussion first — they break
downstream alerting rules.

## Development

Prerequisites: Go (see the version in [`go.mod`](go.mod)).

```sh
git clone https://github.com/mstiri/trivy-epss-kev-exporter
cd trivy-epss-kev-exporter

go build ./...
go test ./...          # unit tests; no cluster required
go vet ./...
gofmt -l .             # should print nothing
```

The pure layers (feed parsers, enrichment, metric lifecycle) are thoroughly
unit-tested and don't need a cluster — that's where most contributions and the
highest-value tests live. The Kubernetes layer is tested with fake clients.

### Guidelines

- Keep the code idiomatic and match the surrounding style; run `gofmt` and
  `go vet`.
- **Add tests** for behavior changes — especially for the pure parsing /
  enrichment logic.
- Keep label cardinality in mind; new labels need a discussion (see the
  cardinality rules in `CLAUDE.md`).
- Update `CLAUDE.md` if you change a design decision or the metric contract.

## Pull requests

1. Fork and create a topic branch.
2. Make your change with tests; ensure `go test ./...`, `go vet ./...`, and
   `gofmt` are clean.
3. Open a PR against `main`. Describe the change and link any related issue.
4. CI (build + test) must pass. A maintainer will review.

## Reporting bugs and features

Open a GitHub issue with a clear description and, for bugs, steps to reproduce
(exporter version, flags, and a redacted sample `VulnerabilityReport` help a lot).
