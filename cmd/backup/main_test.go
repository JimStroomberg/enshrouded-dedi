package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestParseTimestamp(t *testing.T) {
	want := time.Date(2026, time.July, 18, 17, 54, 40, 0, time.UTC)
	for _, name := range []string{
		"backup-20260718-175440.tar.gz",
		"backup-20260718-175440.tgz",
		"manual-prefix-20260718-175440.zip",
	} {
		t.Run(name, func(t *testing.T) {
			got, err := parseTimestamp(name)
			if err != nil {
				t.Fatalf("parseTimestamp(%q): %v", name, err)
			}
			if !got.Equal(want) {
				t.Fatalf("parseTimestamp(%q) = %s, want %s", name, got, want)
			}
		})
	}
}

func TestInternalTokenMiddleware(t *testing.T) {
	const token = "backup-test-token-0123456789abcdef"
	svc := &BackupService{cfg: Config{InternalToken: token}}
	handler := svc.requireInternalToken(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/backups", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("missing token got %d", recorder.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/backups", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("valid token got %d", recorder.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/health", nil)
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("health should be public, got %d", recorder.Code)
	}
}

func TestValidateBackupConfigRejectsDefaults(t *testing.T) {
	cfg := Config{
		InternalToken: "internal-token-0123456789abcdef-0123456789",
		DockerToken:   "controller-token-0123456789abcdef-0123456789",
		AccessKey:     "non-default-access",
		SecretKey:     "non-default-secret",
	}
	if err := validateBackupConfig(cfg); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	cfg.SecretKey = "changeme"
	if err := validateBackupConfig(cfg); err == nil {
		t.Fatal("default secret should be rejected")
	}
}

func TestParseTimestampWithNanoseconds(t *testing.T) {
	got, err := parseTimestamp("backup-20260718-175440.123456789.tar.gz")
	if err != nil {
		t.Fatal(err)
	}
	want := time.Date(2026, time.July, 18, 17, 54, 40, 123456789, time.UTC)
	if !got.Equal(want) {
		t.Fatalf("got %s, want %s", got, want)
	}
}

func TestParseTimestampRejectsInvalidNames(t *testing.T) {
	for _, name := range []string{
		"backup-20260718-175440.tar",
		"backup-invalid.tar.gz",
		"backup-20260718.tar.gz",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseTimestamp(name); err == nil {
				t.Fatalf("parseTimestamp(%q) unexpectedly succeeded", name)
			}
		})
	}
}
