FROM --platform=$BUILDPLATFORM golang:1.27rc2-bookworm@sha256:a2f9daa5dbd9f7a68eb3c32cf91e4f9fc50a11a07f8b9cd9ffa542d2298d9f82 AS builder
ARG TARGETOS=linux
ARG TARGETARCH=amd64
WORKDIR /src
COPY go.mod ./
COPY go.sum ./
COPY cmd/ ./cmd/
COPY internal/ ./internal/
RUN go mod download
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /out/controller ./cmd/controller

FROM debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl && rm -rf /var/lib/apt/lists/*
COPY --from=builder /out/controller /usr/local/bin/controller
EXPOSE 2375
ENTRYPOINT ["/usr/local/bin/controller"]
