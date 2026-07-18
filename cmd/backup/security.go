package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"net/http"
	"strings"
)

func validateBackupConfig(cfg Config) error {
	if _, err := parseMaintenanceWindow(cfg.MaintenanceWindow); err != nil {
		return fmt.Errorf("BACKUP_MAINTENANCE_WINDOW: %w", err)
	}
	if cfg.PlayerNotifications && cfg.PlayerPollInterval <= 0 {
		return fmt.Errorf("BACKUP_PLAYER_POLL_SECONDS must be greater than zero")
	}
	if cfg.AllowInsecure {
		return nil
	}
	if len(cfg.InternalToken) < 32 || knownDefault(cfg.InternalToken) {
		return fmt.Errorf("BACKUP_INTERNAL_TOKEN must be a non-default value of at least 32 characters")
	}
	if len(cfg.DockerToken) < 32 || knownDefault(cfg.DockerToken) {
		return fmt.Errorf("DOCKER_CONTROLLER_TOKEN must be a non-default value of at least 32 characters")
	}
	if knownDefault(cfg.AccessKey) {
		return fmt.Errorf("BACKUP_S3_ACCESS_KEY must be non-default")
	}
	if len(cfg.SecretKey) < 8 || knownDefault(cfg.SecretKey) {
		return fmt.Errorf("BACKUP_S3_SECRET_KEY must be non-default and at least 8 characters")
	}
	return nil
}

func knownDefault(value string) bool {
	normalized := strings.ToLower(strings.TrimSpace(value))
	if strings.Contains(normalized, "change-me") || strings.Contains(normalized, "changeme") || strings.Contains(normalized, "replace-me") {
		return true
	}
	switch normalized {
	case "", "changeme", "change-me", "please-change-me", "admin", "password", "enshrouded":
		return true
	default:
		return false
	}
}

func secureEqual(got, want string) bool {
	gotHash := sha256.Sum256([]byte(got))
	wantHash := sha256.Sum256([]byte(want))
	return subtle.ConstantTimeCompare(gotHash[:], wantHash[:]) == 1
}

func (s *BackupService) requireInternalToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" || r.URL.Path == "/ready" {
			next.ServeHTTP(w, r)
			return
		}
		const prefix = "Bearer "
		header := r.Header.Get("Authorization")
		if !strings.HasPrefix(header, prefix) || !secureEqual(strings.TrimPrefix(header, prefix), s.cfg.InternalToken) {
			w.Header().Set("WWW-Authenticate", "Bearer")
			respondError(w, http.StatusUnauthorized, fmt.Errorf("unauthorized"))
			return
		}
		next.ServeHTTP(w, r)
	})
}
