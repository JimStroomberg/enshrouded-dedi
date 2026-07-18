package main

import (
	"context"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestApplyPreparedRestoreKeepsRollbackAfterHealthyStart(t *testing.T) {
	svc, fake, liveSave, configPath := newRestoreTestService(t, false)
	prepared := newPreparedRestoreForTest(t, filepath.Dir(liveSave), "new-world", `{"name":"new"}`)
	rollback, err := svc.applyPreparedRestore(context.Background(), prepared)
	if err != nil {
		t.Fatal(err)
	}
	assertFileContents(t, filepath.Join(liveSave, "3ad85aea"), "new-world")
	assertFileContents(t, filepath.Join(rollback, "savegame", "3ad85aea"), "old-world")
	assertFileContents(t, configPath, `{"name":"new"}`)
	if fake.starts != 1 {
		t.Fatalf("starts = %d, want 1", fake.starts)
	}
}

func TestApplyPreparedRestoreRollsBackWhenNewSaveIsUnhealthy(t *testing.T) {
	svc, fake, liveSave, configPath := newRestoreTestService(t, true)
	prepared := newPreparedRestoreForTest(t, filepath.Dir(liveSave), "bad-world", `{"name":"bad"}`)
	if _, err := svc.applyPreparedRestore(context.Background(), prepared); err == nil {
		t.Fatal("unhealthy restored save unexpectedly succeeded")
	}
	assertFileContents(t, filepath.Join(liveSave, "3ad85aea"), "old-world")
	assertFileContents(t, configPath, `{"name":"old"}`)
	if fake.starts != 2 {
		t.Fatalf("starts = %d, want 2 (failed restore and rollback)", fake.starts)
	}
}

func newRestoreTestService(t *testing.T, failFirstStart bool) (*BackupService, *fakeDockerTransport, string, string) {
	t.Helper()
	root := t.TempDir()
	liveSave := filepath.Join(root, "savegame")
	writeSavePairForTest(t, liveSave, "old-world")
	configPath := filepath.Join(root, "server", "enshrouded_server.json")
	if err := os.MkdirAll(filepath.Dir(configPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte(`{"name":"old"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	txtPath := filepath.Join(root, "server", "server_config.txt")
	if err := os.WriteFile(txtPath, []byte("SAVE_DIR=/data/savegame\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fake := &fakeDockerTransport{running: true, failFirstStart: failFirstStart}
	svc := &BackupService{
		cfg: Config{
			SaveDir:             liveSave,
			ServerConfigPath:    configPath,
			ServerConfigTxtPath: txtPath,
			EnshroudedContainer: "game",
			HealthTimeout:       time.Second,
		},
		docker: &dockerClient{http: &http.Client{Transport: fake}},
		logger: log.New(io.Discard, "", 0),
	}
	return svc, fake, liveSave, configPath
}

func newPreparedRestoreForTest(t *testing.T, parent, world, config string) *preparedRestore {
	t.Helper()
	root, err := os.MkdirTemp(parent, ".test-restore-stage-")
	if err != nil {
		t.Fatal(err)
	}
	writeSavePairForTest(t, filepath.Join(root, "savegame"), world)
	configDir := filepath.Join(root, "config")
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "enshrouded_server.json"), []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	return &preparedRestore{root: root, saveDir: filepath.Join(root, "savegame"), configDir: configDir}
}

func writeSavePairForTest(t *testing.T, dir, world string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, contents := range map[string]string{
		"3ad85aea":       world,
		"3ad85aea-index": "index",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func assertFileContents(t *testing.T, path, want string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != want {
		t.Fatalf("%s = %q, want %q", path, raw, want)
	}
}

type fakeDockerTransport struct {
	mu             sync.Mutex
	running        bool
	starts         int
	failFirstStart bool
}

func (f *fakeDockerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	status := http.StatusNoContent
	body := ""
	switch {
	case req.Method == http.MethodGet && strings.HasSuffix(req.URL.Path, "/json"):
		status = http.StatusOK
		health := ""
		if f.running {
			health = "healthy"
			if f.failFirstStart && f.starts == 1 {
				health = "unhealthy"
			}
		}
		body = `{"State":{"Running":` + boolJSON(f.running) + `,"Health":{"Status":"` + health + `"}}}`
	case req.Method == http.MethodPost && strings.Contains(req.URL.Path, "/stop"):
		f.running = false
	case req.Method == http.MethodPost && strings.Contains(req.URL.Path, "/start"):
		f.running = true
		f.starts++
	default:
		status = http.StatusNotFound
		body = `{"message":"not found"}`
	}
	return &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
		Request:    req,
	}, nil
}

func boolJSON(v bool) string {
	if v {
		return "true"
	}
	return "false"
}
