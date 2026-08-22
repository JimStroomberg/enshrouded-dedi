# Builder
FROM --platform=$BUILDPLATFORM golang:1.26.6-bookworm@sha256:116d58cbd88c1297624acc6e967a060012422bacf9930927e23fb719189c6f36 AS builder
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
FROM debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
    && useradd --uid 1000 --create-home --shell /usr/sbin/nologin appbackup \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /out/backup /usr/local/bin/backup
USER 1000:1000
EXPOSE 7000
ENTRYPOINT ["/usr/local/bin/backup"]
