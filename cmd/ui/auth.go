package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type loginAttempt struct {
	failures []time.Time
}

type loginLimiter struct {
	mu       sync.Mutex
	attempts map[string]loginAttempt
	max      int
	window   time.Duration
}

func newLoginLimiter(max int, window time.Duration) *loginLimiter {
	return &loginLimiter{attempts: make(map[string]loginAttempt), max: max, window: window}
}

func (l *loginLimiter) allow(ip string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	attempt := l.attempts[ip]
	attempt.failures = recentFailures(attempt.failures, now.Add(-l.window))
	l.attempts[ip] = attempt
	return len(attempt.failures) < l.max
}

func (l *loginLimiter) failure(ip string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	attempt := l.attempts[ip]
	attempt.failures = append(recentFailures(attempt.failures, now.Add(-l.window)), now)
	l.attempts[ip] = attempt
}

func (l *loginLimiter) success(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.attempts, ip)
}

func recentFailures(in []time.Time, cutoff time.Time) []time.Time {
	out := in[:0]
	for _, ts := range in {
		if ts.After(cutoff) {
			out = append(out, ts)
		}
	}
	return out
}

func constantTimeEqual(got, want string) bool {
	gotHash := sha256.Sum256([]byte(got))
	wantHash := sha256.Sum256([]byte(want))
	return subtle.ConstantTimeCompare(gotHash[:], wantHash[:]) == 1
}

func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

func validateUIConfig(cfg UIConfig) error {
	if strings.TrimSpace(cfg.AdminUser) == "" {
		return fmt.Errorf("UI_ADMIN_USERNAME is required")
	}
	if cfg.AllowInsecure {
		return nil
	}
	if len(cfg.AdminPass) < 8 || isKnownDefault(cfg.AdminPass) {
		return fmt.Errorf("UI_ADMIN_PASSWORD must be non-default and at least 8 characters")
	}
	if len(cfg.SessionSecret) < 32 || isKnownDefault(cfg.SessionSecret) {
		return fmt.Errorf("UI_SESSION_SECRET must be a non-default value of at least 32 characters")
	}
	if len(cfg.SessionCrypt) != 32 || isKnownDefault(cfg.SessionCrypt) {
		return fmt.Errorf("UI_SESSION_ENCRYPTION_KEY must be a non-default 32-character value")
	}
	if len(cfg.CSRFKey) < 32 || isKnownDefault(cfg.CSRFKey) {
		return fmt.Errorf("UI_CSRF_KEY must be a non-default value of at least 32 characters")
	}
	if len(cfg.BackupToken) < 32 || isKnownDefault(cfg.BackupToken) {
		return fmt.Errorf("UI_INTERNAL_TOKEN must be a non-default value of at least 32 characters")
	}
	return nil
}

func isKnownDefault(value string) bool {
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
