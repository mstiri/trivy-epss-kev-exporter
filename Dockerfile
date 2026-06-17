# syntax=docker/dockerfile:1

# ---- build stage ----
# Pin the builder to the BUILD platform and cross-compile via GOOS/GOARCH, so
# multi-arch builds stay fast (native Go cross-compile, no QEMU emulation).
FROM --platform=$BUILDPLATFORM golang:1.26 AS build
WORKDIR /src

# Module download is cached separately from the source for fast rebuilds.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Build provenance — override with --build-arg (feeds trivy_exporter_build_info).
ARG VERSION=dev
ARG REVISION=unknown
ARG BRANCH=unknown
ARG BUILD_DATE=unknown
ARG TARGETOS=linux
ARG TARGETARCH=amd64

ENV CGO_ENABLED=0
RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath \
      -ldflags="-s -w \
        -X github.com/prometheus/common/version.Version=${VERSION} \
        -X github.com/prometheus/common/version.Revision=${REVISION} \
        -X github.com/prometheus/common/version.Branch=${BRANCH} \
        -X github.com/prometheus/common/version.BuildDate=${BUILD_DATE}" \
      -o /out/trivy-epss-kev-exporter ./cmd/trivy-epss-kev-exporter

# ---- runtime stage ----
# distroless static:nonroot ships CA certificates (required for the HTTPS feed
# fetches) and a non-root user (uid 65532); nothing else.
FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/trivy-epss-kev-exporter /usr/local/bin/trivy-epss-kev-exporter
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/trivy-epss-kev-exporter"]
