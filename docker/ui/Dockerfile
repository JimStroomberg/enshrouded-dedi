# Builder
FROM --platform=$BUILDPLATFORM golang:1.26.5-bookworm@sha256:1ecb7edf62a0408027bd5729dfd6b1b8766e578e8df93995b225dfd0944eb651 AS builder
WORKDIR /src
ARG TARGETOS
ARG TARGETARCH
COPY go.mod ./
COPY go.sum ./
COPY cmd/ ./cmd/
RUN go mod download
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} go build -o /out/ui ./cmd/ui

# Runtime
FROM debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl && rm -rf /var/lib/apt/lists/*
COPY --from=builder /out/ui /usr/local/bin/ui
USER 65532
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/ui"]
