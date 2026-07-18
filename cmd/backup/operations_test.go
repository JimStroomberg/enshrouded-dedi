package main

import (
	"context"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDiagnosticsRedactsConfiguredPasswords(t *testing.T) {
	root := t.TempDir()
	logDir := filepath.Join(root, "logs")
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		t.Fatal(err)
	}
	serverConfig := filepath.Join(root, "enshrouded_server.json")
	steamAuth := filepath.Join(root, "steam_auth.env")
	const gameSecret = "friend-secret"
	const steamSecret = "steam-secret"
	if err := os.WriteFile(serverConfig, []byte(`{"userGroups":[{"name":"Friend","password":"`+gameSecret+`"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(steamAuth, []byte("STEAM_PASSWORD="+steamSecret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(logDir, "server.log"), []byte("game="+gameSecret+" steam="+steamSecret), 0o600); err != nil {
		t.Fatal(err)
	}
	service := &BackupService{
		cfg:    Config{LogDir: logDir, ServerConfigPath: serverConfig, SteamAuthFile: steamAuth},
		logger: log.New(io.Discard, "", 0),
	}
	logs := service.redactedRecentLogs()
	text := logs["server.log"]
	if strings.Contains(text, gameSecret) || strings.Contains(text, steamSecret) {
		t.Fatalf("diagnostic log leaked a secret: %q", text)
	}
	if strings.Count(text, "[REDACTED]") != 2 {
		t.Fatalf("unexpected redacted log: %q", text)
	}
}

func TestRestoreReplacementFilesAreExactAndSorted(t *testing.T) {
	root := t.TempDir()
	saveDir := filepath.Join(root, "savegame")
	configDir := filepath.Join(root, "config")
	if err := os.MkdirAll(filepath.Join(saveDir, "nested"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for path, contents := range map[string]string{
		filepath.Join(saveDir, "nested", "world"):          "world",
		filepath.Join(saveDir, "characters"):               "characters",
		filepath.Join(configDir, "enshrouded_server.json"): "{}",
	} {
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	files, err := restoreReplacementFiles(&preparedRestore{saveDir: saveDir, configDir: configDir})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"config/enshrouded_server.json", "savegame/characters", "savegame/nested/world"}
	if strings.Join(files, "|") != strings.Join(want, "|") {
		t.Fatalf("got %#v, want %#v", files, want)
	}
}

func newWebhookTestServer(t *testing.T, received chan<- string) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read webhook: %v", err)
			return
		}
		received <- string(data)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)
	return server
}

func TestJobNotificationPostsGenericEvent(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	received := make(chan string, 1)
	server := newWebhookTestServer(t, received)
	manager := newJobManager(ctx, log.New(io.Discard, "", 0), "", server.URL)
	manager.notifyEvent(map[string]interface{}{"type": "players_online", "players": 2})
	select {
	case payload := <-received:
		if !strings.Contains(payload, `"players":2`) || !strings.Contains(payload, `"players_online"`) {
			t.Fatalf("unexpected webhook payload %q", payload)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("webhook event was not received")
	}
}
