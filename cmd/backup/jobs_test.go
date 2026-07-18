package main

import (
	"context"
	"io"
	"log"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestJobManagerTracksCompletionAndAudit(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	manager := newJobManager(ctx, log.New(io.Discard, "", 0), auditPath, "")
	queued, err := manager.enqueue("backup", "test", func(context.Context) (map[string]interface{}, error) {
		return map[string]interface{}{"name": "backup.tar.gz"}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		item, ok := manager.get(queued.ID)
		if ok && item.State == jobSucceeded {
			if item.Result["name"] != "backup.tar.gz" {
				t.Fatalf("unexpected result %#v", item.Result)
			}
			if data, err := os.ReadFile(auditPath); err != nil || len(data) == 0 {
				t.Fatalf("audit not written: %v", err)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("job did not complete")
}
