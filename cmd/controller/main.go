package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type controller struct {
	container string
	token     string
	docker    *http.Client
	logger    *log.Logger
}

func main() {
	container := env("ENSHROUDED_CONTAINER_NAME", "enshrouded")
	token := env("DOCKER_CONTROLLER_TOKEN", "")
	allowInsecure := envBool("ALLOW_INSECURE_DEFAULTS", false)
	if strings.TrimSpace(container) == "" {
		log.Fatal("ENSHROUDED_CONTAINER_NAME is required")
	}
	if !allowInsecure && (len(token) < 32 || knownDefault(token)) {
		log.Fatal("DOCKER_CONTROLLER_TOKEN must be a non-default value of at least 32 characters")
	}

	socket := env("DOCKER_SOCKET", "/var/run/docker.sock")
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "unix", socket)
	}}
	c := &controller{
		container: container,
		token:     token,
		docker:    &http.Client{Transport: transport, Timeout: 30 * time.Second},
		logger:    log.New(os.Stdout, "controller ", log.LstdFlags|log.Lmsgprefix),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"status":"ok"}`)
	})
	mux.HandleFunc("/containers/", c.handleContainer)

	server := &http.Server{
		Addr:              env("CONTROLLER_BIND_ADDR", "0.0.0.0:2375"),
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			c.logger.Printf("shutdown error: %v", err)
		}
	}()

	c.logger.Printf("listening on %s container=%s", server.Addr, container)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		c.logger.Fatalf("http server error: %v", err)
	}
}

func (c *controller) handleContainer(w http.ResponseWriter, r *http.Request) {
	if !authorized(r.Header.Get("Authorization"), c.token) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	name, action, ok := parseContainerPath(r.URL.Path)
	if !ok || name != c.container || !allowedAction(r.Method, action) {
		http.NotFound(w, r)
		return
	}

	query := ""
	if action == "stop" || action == "restart" {
		timeout := 10
		if raw := r.URL.Query().Get("t"); raw != "" {
			if parsed, err := strconv.Atoi(raw); err == nil && parsed >= 0 && parsed <= 60 {
				timeout = parsed
			}
		}
		query = "?t=" + strconv.Itoa(timeout)
	}
	upstreamURL := "http://docker/containers/" + url.PathEscape(c.container) + "/" + action + query
	req, err := http.NewRequestWithContext(r.Context(), r.Method, upstreamURL, nil)
	if err != nil {
		http.Error(w, "invalid request", http.StatusInternalServerError)
		return
	}
	resp, err := c.docker.Do(req)
	if err != nil {
		c.logger.Printf("docker action=%s error=%v", action, err)
		http.Error(w, "docker unavailable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	if contentType := resp.Header.Get("Content-Type"); contentType != "" {
		w.Header().Set("Content-Type", contentType)
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, io.LimitReader(resp.Body, 4<<20))
}

func parseContainerPath(path string) (string, string, bool) {
	rest := strings.TrimPrefix(path, "/containers/")
	parts := strings.Split(rest, "/")
	if len(parts) != 2 {
		return "", "", false
	}
	name, err := url.PathUnescape(parts[0])
	return name, parts[1], err == nil && name != "" && parts[1] != ""
}

func allowedAction(method, action string) bool {
	if method == http.MethodGet && action == "json" {
		return true
	}
	if method == http.MethodPost {
		return action == "start" || action == "stop" || action == "restart"
	}
	return false
}

func authorized(header, token string) bool {
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return false
	}
	gotHash := sha256.Sum256([]byte(strings.TrimPrefix(header, prefix)))
	wantHash := sha256.Sum256([]byte(token))
	return subtle.ConstantTimeCompare(gotHash[:], wantHash[:]) == 1
}

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func envBool(key string, fallback bool) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(key))) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return fallback
	}
}

func knownDefault(value string) bool {
	normalized := strings.ToLower(strings.TrimSpace(value))
	if strings.Contains(normalized, "change-me") || strings.Contains(normalized, "changeme") || strings.Contains(normalized, "replace-me") {
		return true
	}
	switch normalized {
	case "", "changeme", "change-me", "please-change-me", "admin", "password":
		return true
	default:
		return false
	}
}
