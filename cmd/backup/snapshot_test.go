package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCreateSnapshotStageAndVerifyManifest(t *testing.T) {
	root := t.TempDir()
	saveDir := filepath.Join(root, "savegame")
	if err := os.MkdirAll(saveDir, 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"3ad85aea":         "world",
		"3ad85aea-index":   "world-index",
		"characters":       "characters",
		"characters-index": "characters-index",
	}
	for name, contents := range files {
		if err := os.WriteFile(filepath.Join(saveDir, name), []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	serverConfig := filepath.Join(root, "enshrouded_server.json")
	if err := os.WriteFile(serverConfig, []byte(`{"name":"test"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, time.July, 18, 20, 0, 0, 0, time.UTC)
	stage, err := createSnapshotStage(saveDir, map[string]string{"enshrouded_server.json": serverConfig}, "12345", now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(stage) })

	payload, configDir, manifest, err := restorePayload(stage)
	if err != nil {
		t.Fatal(err)
	}
	if payload != filepath.Join(stage, "savegame") {
		t.Fatalf("payload = %q", payload)
	}
	if configDir != filepath.Join(stage, "config") {
		t.Fatalf("configDir = %q", configDir)
	}
	if manifest == nil || manifest.GameBuild != "12345" || !manifest.CreatedAt.Equal(now) {
		t.Fatalf("unexpected manifest: %#v", manifest)
	}
	if !regularFileExists(filepath.Join(configDir, "enshrouded_server.json")) {
		t.Fatal("server config missing from snapshot")
	}
}

func TestVerifyBackupManifestRejectsTampering(t *testing.T) {
	root := t.TempDir()
	saveDir := filepath.Join(root, "savegame")
	if err := os.MkdirAll(saveDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(saveDir, "world"), []byte("before"), 0o600); err != nil {
		t.Fatal(err)
	}
	stage, err := createSnapshotStage(saveDir, nil, "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(stage) })
	if err := os.WriteFile(filepath.Join(stage, "savegame", "world"), []byte("after"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := verifyBackupManifest(stage); err == nil {
		t.Fatal("tampered snapshot unexpectedly passed verification")
	}
}

func TestValidateSaveDirectoryRequiresCompletePairs(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "3ad85aea"), []byte("world"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateSaveDirectory(dir); err == nil {
		t.Fatal("incomplete world pair unexpectedly passed validation")
	}
}

func TestPathWithinBase(t *testing.T) {
	base := filepath.Join(string(filepath.Separator), "data", "save")
	if !pathWithinBase(base, filepath.Join(base, "world")) {
		t.Fatal("child path rejected")
	}
	if pathWithinBase(base, filepath.Join(string(filepath.Separator), "data", "save-evil", "world")) {
		t.Fatal("sibling prefix path accepted")
	}
}
