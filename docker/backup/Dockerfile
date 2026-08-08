# Builder
FROM --platform=$BUILDPLATFORM golang:1.26.5-bookworm@sha256:1ecb7edf62a0408027bd5729dfd6b1b8766e578e8df93995b225dfd0944eb651 AS builder
WORKDIR /src
ARG TARGETOS
ARG TARGETARCH
COPY go.mod ./
COPY go.sum ./
COPY cmd/ ./cmd/
COPY internal/ ./internal/
RUN go mod download
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} go build -o /out/backup ./cmd/backup

# Runtime
FROM debian:bookworm-slim@sha256:abd67ffcfa541b485a3dff59865ab629aa048a6c613e639d36e7456b0b229241
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
    && useradd --uid 1000 --create-home --shell /usr/sbin/nologin appbackup \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /out/backup /usr/local/bin/backup
USER 1000:1000
EXPOSE 7000
ENTRYPOINT ["/usr/local/bin/backup"]
