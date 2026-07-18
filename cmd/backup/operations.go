package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"
)

type readinessReport struct {
	Status string            `json:"status"`
	Checks map[string]string `json:"checks"`
}

func (s *BackupService) handleReady(w http.ResponseWriter, r *http.Request) {
	report, err := s.readiness(r.Context())
	if err != nil {
		respondJSONStatus(w, http.StatusServiceUnavailable, report)
		return
	}
	respondJSON(w, report)
}

func (s *BackupService) readiness(ctx context.Context) (readinessReport, error) {
	report := readinessReport{Status: "ready", Checks: map[string]string{}}
	var result error
	if info, err := os.Stat(s.cfg.SaveDir); err != nil || !info.IsDir() {
		report.Checks["save_path"] = "unavailable"
		result = errors.Join(result, fmt.Errorf("save path unavailable"))
	} else if probe, err := os.CreateTemp(s.cfg.SaveDir, ".readiness-*"); err != nil {
		report.Checks["save_path"] = "not writable"
		result = errors.Join(result, err)
	} else {
		probePath := probe.Name()
		_ = probe.Close()
		_ = os.Remove(probePath)
		report.Checks["save_path"] = "ok"
	}
	if _, err := s.containerStatus(ctx); err != nil {
		report.Checks["game_control"] = "unavailable"
		result = errors.Join(result, err)
	} else {
		report.Checks["game_control"] = "ok"
	}
	if exists, err := s.s3.BucketExists(ctx, s.cfg.Bucket); err != nil || !exists {
		report.Checks["object_storage"] = "unavailable"
		if err == nil {
			err = fmt.Errorf("bucket does not exist")
		}
		result = errors.Join(result, err)
	} else {
		if storageErr := s.verifyObjectStorage(ctx); storageErr != nil {
			report.Checks["object_storage"] = "unavailable"
			result = errors.Join(result, storageErr)
		} else {
			report.Checks["object_storage"] = "ok"
		}
	}
	if result != nil {
		report.Status = "not_ready"
	}
	return report, result
}

func (s *BackupService) verifyObjectStorage(ctx context.Context) (err error) {
	id, err := randomID()
	if err != nil {
		return err
	}
	name := ".readiness/probe-" + id
	payload := []byte("ok")
	upload, err := s.s3.PutObject(ctx, s.cfg.Bucket, name, bytes.NewReader(payload), int64(len(payload)), minio.PutObjectOptions{ContentType: "text/plain"})
	if err != nil {
		return fmt.Errorf("write readiness probe: %w", err)
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		cleanupErr := s.s3.RemoveObject(cleanupCtx, s.cfg.Bucket, name, minio.RemoveObjectOptions{VersionID: upload.VersionID})
		if cleanupErr != nil {
			err = errors.Join(err, fmt.Errorf("remove readiness probe: %w", cleanupErr))
		}
	}()

	object, err := s.s3.GetObject(ctx, s.cfg.Bucket, name, minio.GetObjectOptions{VersionID: upload.VersionID})
	if err != nil {
		return fmt.Errorf("read readiness probe: %w", err)
	}
	defer object.Close()
	data, err := io.ReadAll(io.LimitReader(object, int64(len(payload)+1)))
	if err != nil {
		return fmt.Errorf("read readiness probe: %w", err)
	}
	if !bytes.Equal(data, payload) {
		return fmt.Errorf("readiness probe contents did not match")
	}
	return nil
}

func (s *BackupService) handleOperationsStatus(w http.ResponseWriter, r *http.Request) {
	status, err := s.operationsStatus(r.Context())
	if err != nil {
		respondError(w, http.StatusInternalServerError, err)
		return
	}
	respondJSON(w, status)
}

func (s *BackupService) operationsStatus(ctx context.Context) (map[string]interface{}, error) {
	items, err := s.listBackups(ctx)
	if err != nil {
		return nil, err
	}
	status := map[string]interface{}{
		"scheduled_interval_hours": s.cfg.IntervalHours,
		"recent_jobs":              s.jobs.list(10),
		"restart_policy": map[string]interface{}{
			"require_empty":      s.cfg.RestartRequireEmpty,
			"maintenance_window": s.cfg.MaintenanceWindow,
			"timezone":           getenv("TZ", "UTC"),
		},
	}
	if s.cfg.IntervalHours > 0 {
		interval := time.Duration(s.cfg.IntervalHours) * time.Hour
		periods := time.Since(s.startedAt)/interval + 1
		status["next_scheduled_run"] = s.startedAt.Add(periods * interval)
	}
	if len(items) > 0 {
		sort.Slice(items, func(i, j int) bool { return items[i].LastModified.After(items[j].LastModified) })
		latest := items[0]
		object, statErr := s.s3.StatObject(ctx, s.cfg.Bucket, latest.Key, minio.StatObjectOptions{})
		backup := map[string]interface{}{
			"name":          latest.Key,
			"size":          latest.Size,
			"last_modified": latest.LastModified,
			"age_seconds":   int64(time.Since(latest.LastModified).Seconds()),
		}
		if statErr == nil {
			if checksum := metadataValue(object.UserMetadata, "sha256"); checksum != "" {
				backup["checksum"] = checksum
				backup["checksum_status"] = "recorded"
			}
			backup["manifest_schema"] = metadataValue(object.UserMetadata, "manifest-schema")
		}
		status["last_backup"] = backup
	}
	return status, nil
}

func metadataValue(metadata map[string]string, name string) string {
	for key, value := range metadata {
		key = strings.ToLower(strings.TrimPrefix(key, "x-amz-meta-"))
		if key == strings.ToLower(name) {
			return value
		}
	}
	return ""
}

func (s *BackupService) handleBackupPreview(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if !isSafeBackupName(name) {
		respondError(w, http.StatusBadRequest, fmt.Errorf("invalid backup name"))
		return
	}
	archivePath, size, err := s.downloadBackupArchive(r.Context(), name)
	if err != nil {
		respondError(w, http.StatusInternalServerError, err)
		return
	}
	defer os.Remove(archivePath)
	prepared, err := s.prepareRestoreArchive(archivePath)
	if err != nil {
		respondError(w, http.StatusUnprocessableEntity, err)
		return
	}
	defer prepared.cleanup()
	replacedFiles, err := restoreReplacementFiles(prepared)
	if err != nil {
		respondError(w, http.StatusUnprocessableEntity, err)
		return
	}
	currentBuild := readSteamBuild(s.cfg.SteamAppManifest)
	preview := map[string]interface{}{
		"name":               name,
		"archive_size":       size,
		"validated":          true,
		"legacy":             prepared.manifest == nil,
		"will_replace":       replacedFiles,
		"current_game_build": currentBuild,
	}
	if prepared.manifest != nil {
		preview["schema_version"] = prepared.manifest.SchemaVersion
		preview["created_at"] = prepared.manifest.CreatedAt
		preview["game_build"] = prepared.manifest.GameBuild
		preview["files"] = prepared.manifest.Files
		preview["file_count"] = len(prepared.manifest.Files)
		compatibility := "unknown"
		if prepared.manifest.GameBuild != "" && currentBuild != "" {
			if prepared.manifest.GameBuild == currentBuild {
				compatibility = "matching build"
			} else {
				compatibility = "different build"
			}
		}
		preview["build_compatibility"] = compatibility
	}
	respondJSON(w, preview)
}

func restoreReplacementFiles(prepared *preparedRestore) ([]string, error) {
	var files []string
	if err := filepath.Walk(prepared.saveDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		relative, err := filepath.Rel(prepared.saveDir, path)
		if err != nil {
			return err
		}
		files = append(files, filepath.ToSlash(filepath.Join("savegame", relative)))
		return nil
	}); err != nil {
		return nil, err
	}
	if prepared.configDir != "" {
		for _, name := range []string{"enshrouded_server.json", "server_config.txt"} {
			if regularFileExists(filepath.Join(prepared.configDir, name)) {
				files = append(files, "config/"+name)
			}
		}
	}
	sort.Strings(files)
	return files, nil
}

func (s *BackupService) downloadBackupArchive(ctx context.Context, name string) (string, int64, error) {
	obj, err := s.s3.GetObject(ctx, s.cfg.Bucket, name, minio.GetObjectOptions{})
	if err != nil {
		return "", 0, err
	}
	defer obj.Close()
	stat, err := obj.Stat()
	if err != nil {
		return "", 0, err
	}
	tmp, err := os.CreateTemp("", "enshrouded-preview-*")
	if err != nil {
		return "", 0, err
	}
	path := tmp.Name()
	if _, err := io.Copy(tmp, io.LimitReader(obj, s.cfg.MaxExtractBytes+1)); err != nil {
		tmp.Close()
		_ = os.Remove(path)
		return "", 0, err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(path)
		return "", 0, err
	}
	return path, stat.Size, nil
}

func (s *BackupService) handleDiagnostics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", "attachment; filename=enshrouded-diagnostics.tar.gz")
	gz := gzip.NewWriter(w)
	tw := tar.NewWriter(gz)
	defer gz.Close()
	defer tw.Close()

	addJSON := func(name string, value interface{}) {
		data, _ := json.MarshalIndent(value, "", "  ")
		_ = addDiagnosticFile(tw, name, append(data, '\n'))
	}
	ready, _ := s.readiness(r.Context())
	operations, _ := s.operationsStatus(r.Context())
	status, _ := s.containerStatus(r.Context())
	config, _ := s.readServerConfig()
	addJSON("readiness.json", ready)
	addJSON("operations.json", operations)
	addJSON("game-status.json", status)
	addJSON("server-config-redacted.json", config)
	addJSON("versions.json", map[string]interface{}{
		"game_build":         readSteamBuild(s.cfg.SteamAppManifest),
		"manifest_schema":    backupManifestSchema,
		"service_started_at": s.startedAt,
	})
	addJSON("recent-jobs.json", s.jobs.list(50))
	addJSON("recent-logs-redacted.json", s.redactedRecentLogs())
}

func addDiagnosticFile(tw *tar.Writer, name string, data []byte) error {
	header := &tar.Header{Name: name, Mode: 0o600, Size: int64(len(data)), ModTime: time.Now().UTC()}
	if err := tw.WriteHeader(header); err != nil {
		return err
	}
	_, err := io.Copy(tw, bytes.NewReader(data))
	return err
}

func (s *BackupService) redactedRecentLogs() map[string]string {
	entries, err := os.ReadDir(s.cfg.LogDir)
	if err != nil {
		return map[string]string{"status": "logs unavailable"}
	}
	secrets := s.diagnosticSecrets()
	result := map[string]string{}
	count := 0
	for i := len(entries) - 1; i >= 0 && count < 8; i-- {
		entry := entries[i]
		if entry.IsDir() {
			continue
		}
		path := filepath.Join(s.cfg.LogDir, entry.Name())
		data, err := readTail(path, 64<<10)
		if err != nil {
			continue
		}
		text := string(data)
		for _, secret := range secrets {
			if len(secret) >= 3 {
				text = strings.ReplaceAll(text, secret, "[REDACTED]")
			}
		}
		result[entry.Name()] = text
		count++
	}
	return result
}

func (s *BackupService) diagnosticSecrets() []string {
	var secrets []string
	if raw, err := os.ReadFile(s.cfg.SteamAuthFile); err == nil {
		for _, line := range strings.Split(string(raw), "\n") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 && (strings.Contains(parts[0], "PASSWORD") || strings.Contains(parts[0], "GUARD")) {
				value := strings.TrimSpace(parts[1])
				if strings.HasSuffix(parts[0], "_B64") {
					if decoded, err := base64.StdEncoding.DecodeString(value); err == nil {
						value = string(decoded)
					}
				}
				secrets = append(secrets, value)
			}
		}
	}
	if raw, err := os.ReadFile(s.cfg.ServerConfigPath); err == nil {
		var doc interface{}
		if json.Unmarshal(raw, &doc) == nil {
			collectPasswordValues(doc, &secrets)
		}
	}
	return secrets
}

func collectPasswordValues(value interface{}, secrets *[]string) {
	switch typed := value.(type) {
	case map[string]interface{}:
		for key, item := range typed {
			if strings.Contains(strings.ToLower(key), "password") {
				if text, ok := item.(string); ok && text != "" {
					*secrets = append(*secrets, text)
				}
			}
			collectPasswordValues(item, secrets)
		}
	case []interface{}:
		for _, item := range typed {
			collectPasswordValues(item, secrets)
		}
	}
}

func readTail(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	start := info.Size() - limit
	if start < 0 {
		start = 0
	}
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return nil, err
	}
	return io.ReadAll(io.LimitReader(f, limit))
}

func (s *BackupService) handleMetrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	jobs := s.jobs.list(100)
	counts := map[jobState]int{}
	for _, item := range jobs {
		counts[item.State]++
	}
	fmt.Fprintf(w, "enshrouded_control_jobs{state=%q} %d\n", jobQueued, counts[jobQueued])
	fmt.Fprintf(w, "enshrouded_control_jobs{state=%q} %d\n", jobRunning, counts[jobRunning])
	fmt.Fprintf(w, "enshrouded_control_jobs{state=%q} %d\n", jobSucceeded, counts[jobSucceeded])
	fmt.Fprintf(w, "enshrouded_control_jobs{state=%q} %d\n", jobFailed, counts[jobFailed])
	fmt.Fprintf(w, "enshrouded_control_uptime_seconds %d\n", int64(time.Since(s.startedAt).Seconds()))
}
