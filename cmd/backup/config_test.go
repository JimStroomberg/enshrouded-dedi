package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestUpdateServerConfigPreservesUnknownFields(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "enshrouded_server.json")
	textPath := filepath.Join(dir, "server_config.txt")
	original := `{
  "name": "old",
  "futureField": {"nested": 42},
  "userGroups": [{"name":"Friend","password":"secret","futurePermission":true}],
  "gameSettings": {"futureGameSetting": 3.5}
}`
	if err := os.WriteFile(configPath, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(textPath, []byte("SERVER_NAME=old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	service := &BackupService{
		cfg:    Config{ServerConfigPath: configPath, ServerConfigTxtPath: textPath},
		logger: log.New(io.Discard, "", 0),
	}
	name := "new"
	if err := service.updateServerConfig(&serverConfigPayload{Name: &name}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]interface{}
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	if document["name"] != "new" {
		t.Fatalf("name not updated: %#v", document["name"])
	}
	future, ok := document["futureField"].(map[string]interface{})
	if !ok || future["nested"] != float64(42) {
		t.Fatalf("unknown field was not preserved: %#v", document["futureField"])
	}
	settings := document["gameSettings"].(map[string]interface{})
	if settings["futureGameSetting"] != 3.5 {
		t.Fatalf("unknown game setting was not preserved: %#v", settings)
	}
}

func TestApplyConfigTransactionRollsBackStoppedServer(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "enshrouded_server.json")
	textPath := filepath.Join(dir, "server_config.txt")
	if err := os.WriteFile(configPath, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	controller := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/containers/game/json" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"State":{"Running":false}}`)
	}))
	defer controller.Close()

	service := &BackupService{
		cfg: Config{
			ServerConfigPath:    configPath,
			ServerConfigTxtPath: textPath,
			EnshroudedContainer: "game",
			HealthTimeout:       time.Second,
		},
		docker: newDockerClient(controller.URL, ""),
		logger: log.New(io.Discard, "", 0),
	}
	wantErr := errors.New("mutation failed")
	err := service.applyConfigTransaction(context.Background(), func() error {
		if err := os.WriteFile(configPath, []byte("changed"), 0o600); err != nil {
			return err
		}
		if err := os.WriteFile(textPath, []byte("created"), 0o600); err != nil {
			return err
		}
		return wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("got %v, want mutation error", err)
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "original" {
		t.Fatalf("config was not restored: %q", data)
	}
	if _, err := os.Stat(textPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("new config file was not removed: %v", err)
	}
}

func TestApplyConfigTransactionRestoresConfigAfterUnhealthyRestart(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "enshrouded_server.json")
	textPath := filepath.Join(dir, "server_config.txt")
	if err := os.WriteFile(configPath, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(textPath, []byte("original-text"), 0o600); err != nil {
		t.Fatal(err)
	}
	fake := &fakeDockerTransport{running: true, failFirstStart: true}
	service := &BackupService{
		cfg: Config{
			ServerConfigPath:    configPath,
			ServerConfigTxtPath: textPath,
			EnshroudedContainer: "game",
			HealthTimeout:       100 * time.Millisecond,
		},
		docker: &dockerClient{http: &http.Client{Transport: fake}},
		logger: log.New(io.Discard, "", 0),
	}
	err := service.applyConfigTransaction(context.Background(), func() error {
		return os.WriteFile(configPath, []byte("changed"), 0o600)
	})
	if err == nil {
		t.Fatal("unhealthy updated config unexpectedly succeeded")
	}
	data, readErr := os.ReadFile(configPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(data) != "original" {
		t.Fatalf("config was not restored: %q", data)
	}
	if fake.starts != 2 {
		t.Fatalf("starts = %d, want failed start plus rollback start", fake.starts)
	}
}
