package main

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// Config holds env-driven configuration.
type Config struct {
	SaveDir             string
	Endpoint            string
	AccessKey           string
	SecretKey           string
	Bucket              string
	UseSSL              bool
	IntervalHours       int
	RetentionDailies    int
	RetentionWeeklies   int
	RetentionMonthlies  int
	BindAddr            string
	EnshroudedContainer string
	LogLevel            string
}

func getenv(key, def string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return def
}

func atoiEnv(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}
	return def
}

func parseBoolEnv(key string, def bool) bool {
	if v := os.Getenv(key); v != "" {
		switch strings.ToLower(v) {
		case "1", "true", "yes", "on":
			return true
		case "0", "false", "no", "off":
			return false
		}
	}
	return def
}

// BackupService implements backup/restore endpoints.
type BackupService struct {
	cfg    Config
	s3     *minio.Client
	docker *dockerClient
	logger *log.Logger
}

func main() {
	endpoint := getenv("BACKUP_S3_ENDPOINT", "http://minio:9000")
	useSSL := parseBoolEnv("BACKUP_S3_SSL", strings.HasPrefix(endpoint, "https://"))
	endpoint = strings.TrimPrefix(strings.TrimPrefix(endpoint, "https://"), "http://")

	cfg := Config{
		SaveDir:             getenv("BACKUP_SAVE_DIR", "/data/savegame"),
		Endpoint:            endpoint,
		AccessKey:           getenv("BACKUP_S3_ACCESS_KEY", ""),
		SecretKey:           getenv("BACKUP_S3_SECRET_KEY", ""),
		Bucket:              getenv("BACKUP_S3_BUCKET", "enshrouded-backups"),
		UseSSL:              useSSL,
		IntervalHours:       atoiEnv("BACKUP_INTERVAL_HOURS", 24),
		RetentionDailies:    atoiEnv("BACKUP_RETENTION_DAILIES", 14),
		RetentionWeeklies:   atoiEnv("BACKUP_RETENTION_WEEKLIES", 8),
		RetentionMonthlies:  atoiEnv("BACKUP_RETENTION_MONTHLIES", 12),
		BindAddr:            getenv("BACKUP_BIND_ADDR", "0.0.0.0:7000"),
		EnshroudedContainer: getenv("ENSHROUDED_CONTAINER_NAME", "enshrouded"),
		LogLevel:            strings.ToLower(getenv("BACKUP_LOG_LEVEL", "info")),
	}

	logger := log.New(os.Stdout, "backup ", log.LstdFlags|log.Lmsgprefix)

	ctx := context.Background()

	s3Client, err := minio.New(cfg.Endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.AccessKey, cfg.SecretKey, ""),
		Secure: cfg.UseSSL,
	})
	if err != nil {
		logger.Fatalf("minio init: %v", err)
	}

	dockerClient := newDockerClient(getenv("DOCKER_HOST", "/var/run/docker.sock"))

	svc := &BackupService{cfg: cfg, s3: s3Client, docker: dockerClient, logger: logger}

	if err := svc.ensureBucket(ctx); err != nil {
		logger.Printf("warn: unable to verify bucket %s: %v", cfg.Bucket, err)
	}

	if cfg.IntervalHours > 0 {
		go svc.startScheduler(ctx)
	}

	r := mux.NewRouter()
	r.HandleFunc("/health", svc.handleHealth).Methods(http.MethodGet)
	r.HandleFunc("/backups", svc.handleListBackups).Methods(http.MethodGet)
	r.HandleFunc("/backup", svc.handleCreateBackup).Methods(http.MethodPost)
	r.HandleFunc("/restore", svc.handleRestoreBackup).Methods(http.MethodPost)
	r.HandleFunc("/upload", svc.handleUploadRestore).Methods(http.MethodPost)
	r.HandleFunc("/logs", svc.handleLogs).Methods(http.MethodGet)
	r.HandleFunc("/server/restart", svc.handleRestartServer).Methods(http.MethodPost)
	r.HandleFunc("/server/update", svc.handleUpdateServer).Methods(http.MethodPost)
	r.HandleFunc("/status", svc.handleStatus).Methods(http.MethodGet)
	r.HandleFunc("/steam/auth", svc.handleSteamAuth).Methods(http.MethodPost)
	r.HandleFunc("/steam/anonymous", svc.handleSteamAnonymous).Methods(http.MethodPost)
	r.HandleFunc("/steam/state", svc.handleSteamState).Methods(http.MethodGet)

	logger.Printf("listening on %s", cfg.BindAddr)
	if err := http.ListenAndServe(cfg.BindAddr, r); err != nil {
		logger.Fatalf("http server failed: %v", err)
	}
}

func (s *BackupService) ensureBucket(ctx context.Context) error {
	exists, err := s.s3.BucketExists(ctx, s.cfg.Bucket)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}
	return s.s3.MakeBucket(ctx, s.cfg.Bucket, minio.MakeBucketOptions{})
}

func (s *BackupService) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `{"status":"ok"}`)
}

func (s *BackupService) handleListBackups(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	items, err := s.listBackups(ctx)
	if err != nil {
		respondError(w, http.StatusInternalServerError, err)
		return
	}
	respondJSON(w, items)
}

func (s *BackupService) handleCreateBackup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name, err := s.createBackup(ctx)
	if err != nil {
		respondError(w, http.StatusInternalServerError, err)
		return
	}
	respondJSON(w, map[string]string{"name": name})
}

func (s *BackupService) handleRestoreBackup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	type payload struct {
		Name string `json:"name"`
	}
	var p payload
	if err := decodeJSON(r, &p); err != nil || p.Name == "" {
		respondError(w, http.StatusBadRequest, errors.New("name required"))
		return
	}
	if err := s.restoreBackup(ctx, p.Name); err != nil {
		respondError(w, http.StatusInternalServerError, err)
		return
	}
	respondJSON(w, map[string]string{"restored": p.Name})
}

func (s *BackupService) handleUploadRestore(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	r.Body = http.MaxBytesReader(w, r.Body, 512<<20) // 512MB limit
	if err := r.ParseMultipartForm(512 << 20); err != nil {
		respondError(w, http.StatusBadRequest, fmt.Errorf("invalid upload: %w", err))
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		respondError(w, http.StatusBadRequest, errors.New("file field required"))
		return
	}
	defer file.Close()
	if err := s.uploadAndRestore(ctx, header.Filename, file); err != nil {
		respondError(w, http.StatusInternalServerError, err)
		return
	}
	respondJSON(w, map[string]string{"restored": header.Filename})
}

func (s *BackupService) handleLogs(w http.ResponseWriter, r *http.Request) {
	logDir := filepath.Join(s.cfg.SaveDir, "..", "logs")
	if _, err := os.Stat(logDir); err != nil {
		respondError(w, http.StatusNotFound, errors.New("no logs found"))
		return
	}
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", "attachment; filename=logs.tar.gz")
	gz := gzip.NewWriter(w)
	defer gz.Close()
	tw := tar.NewWriter(gz)
	defer tw.Close()

	if err := filepath.Walk(logDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(logDir, path)
		if err != nil {
			return err
		}
		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		header.Name = rel
		if err := tw.WriteHeader(header); err != nil {
			return err
		}
		if info.Mode().IsRegular() {
			f, err := os.Open(path)
			if err != nil {
				return err
			}
			if _, err := io.Copy(tw, f); err != nil {
				f.Close()
				return err
			}
			f.Close()
		}
		return nil
	}); err != nil {
		respondError(w, http.StatusInternalServerError, err)
		return
	}
}

func (s *BackupService) handleRestartServer(w http.ResponseWriter, r *http.Request) {
	if err := s.restartContainer(r.Context()); err != nil {
		respondError(w, http.StatusInternalServerError, err)
		return
	}
	respondJSON(w, map[string]string{"status": "restarting"})
}

func (s *BackupService) handleUpdateServer(w http.ResponseWriter, r *http.Request) {
	if err := s.restartContainer(r.Context()); err != nil {
		respondError(w, http.StatusInternalServerError, err)
		return
	}
	respondJSON(w, map[string]string{"status": "update-triggered"})
}

func (s *BackupService) handleStatus(w http.ResponseWriter, r *http.Request) {
	info, err := s.containerStatus(r.Context())
	if err != nil {
		respondError(w, http.StatusInternalServerError, err)
		return
	}
	respondJSON(w, info)
}

func (s *BackupService) handleSteamAuth(w http.ResponseWriter, r *http.Request) {
	type payload struct {
		Username  string `json:"username"`
		Password  string `json:"password"`
		GuardCode string `json:"guard_code"`
	}
	var p payload
	if err := decodeJSON(r, &p); err != nil {
		respondError(w, http.StatusBadRequest, fmt.Errorf("invalid payload: %w", err))
		return
	}
	if strings.TrimSpace(p.Username) == "" || strings.TrimSpace(p.Password) == "" {
		respondError(w, http.StatusBadRequest, errors.New("username and password required"))
		return
	}
	if err := s.writeSteamAuthFile(p.Username, p.Password, p.GuardCode); err != nil {
		respondError(w, http.StatusInternalServerError, err)
		return
	}
	// Kick off a quick restart so the guard code is used immediately.
	go func() {
		if err := s.restartContainer(context.Background()); err != nil {
			s.logger.Printf("steam auth: restart failed: %v", err)
		}
	}()
	respondJSON(w, map[string]string{"status": "stored"})
}

func (s *BackupService) handleSteamState(w http.ResponseWriter, r *http.Request) {
	state, err := s.readSteamState()
	if err != nil {
		respondError(w, http.StatusInternalServerError, err)
		return
	}
	respondJSON(w, state)
}

func (s *BackupService) handleSteamAnonymous(w http.ResponseWriter, r *http.Request) {
	if err := s.writeSteamAnonymous(); err != nil {
		respondError(w, http.StatusInternalServerError, err)
		return
	}
	go func() {
		if err := s.restartContainer(context.Background()); err != nil {
			s.logger.Printf("steam anonymous: restart failed: %v", err)
		}
	}()
	respondJSON(w, map[string]string{"status": "anonymous"})
}

func (s *BackupService) writeSteamAuthFile(user, pass, guard string) error {
	authPath := s.steamAuthPath()
	content := fmt.Sprintf("STEAM_CHOSEN=1\nSTEAM_LOGIN=user\nSTEAM_USERNAME=%s\nSTEAM_PASSWORD=%s\n", user, pass)
	if strings.TrimSpace(guard) != "" {
		content += fmt.Sprintf("STEAM_GUARD_CODE=%s\n", guard)
	}
	if err := os.WriteFile(authPath, []byte(content), 0o600); err != nil {
		return err
	}
	// The game container runs as uid/gid 1000 (steam). Best-effort chown so it can read the file.
	_ = os.Chown(authPath, 1000, 1000)
	return nil
}

func (s *BackupService) removeSteamAuthFile() error {
	authPath := s.steamAuthPath()
	if err := os.Remove(authPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (s *BackupService) writeSteamAnonymous() error {
	authPath := s.steamAuthPath()
	content := "STEAM_CHOSEN=1\nSTEAM_LOGIN=anonymous\n"
	if err := os.WriteFile(authPath, []byte(content), 0o600); err != nil {
		return err
	}
	_ = os.Chown(authPath, 1000, 1000)
	return nil
}

type steamState struct {
	Mode      string `json:"mode"`                // anonymous | user | unset
	Username  string `json:"username"`            // optional
	HasCreds  bool   `json:"has_creds"`           // true if username/password present
	GuardHint bool   `json:"guard_hint"`
	Chosen    bool   `json:"chosen"`
	LastError string `json:"last_error,omitempty"`
}

func (s *BackupService) readSteamState() (*steamState, error) {
	authPath := s.steamAuthPath()
	data, err := os.ReadFile(authPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &steamState{Mode: "unset"}, nil
		}
		return nil, err
	}
	lines := strings.Split(string(data), "\n")
	state := &steamState{Mode: "user"}
	chosen := false
	for _, ln := range lines {
		if strings.HasPrefix(ln, "STEAM_LOGIN=") {
			val := strings.TrimSpace(strings.TrimPrefix(ln, "STEAM_LOGIN="))
			if val != "" {
				state.Mode = val
			}
		}
		if strings.HasPrefix(ln, "STEAM_CHOSEN=") {
			val := strings.TrimSpace(strings.TrimPrefix(ln, "STEAM_CHOSEN="))
			if val != "" && strings.ToLower(val) != "0" {
				chosen = true
			}
		}
		if strings.HasPrefix(ln, "STEAM_USERNAME=") {
			state.Username = strings.TrimSpace(strings.TrimPrefix(ln, "STEAM_USERNAME="))
		}
		if strings.HasPrefix(ln, "STEAM_PASSWORD=") && strings.TrimSpace(strings.TrimPrefix(ln, "STEAM_PASSWORD=")) != "" {
			state.HasCreds = true
		}
		if strings.HasPrefix(ln, "STEAM_GUARD_CODE=") && strings.TrimSpace(strings.TrimPrefix(ln, "STEAM_GUARD_CODE=")) != "" {
			state.GuardHint = true
		}
	}
	state.Chosen = chosen
	if state.Mode == "user" && !state.HasCreds {
		state.Mode = "unset"
	}
	if !state.Chosen {
		state.Mode = "unset"
	}
	state.LastError = s.lastSteamError()
	return state, nil
}

func (s *BackupService) lastSteamError() string {
	logPath := filepath.Join(filepath.Dir(s.cfg.SaveDir), "..", "logs", "steamcmd.log")
	data, err := os.ReadFile(logPath)
	if err != nil {
		return ""
	}
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	// Look from bottom for an error-ish line.
	for i := len(lines) - 1; i >= 0; i-- {
		ln := strings.TrimSpace(lines[i])
		lc := strings.ToLower(ln)
		if strings.Contains(lc, "error!") || strings.Contains(lc, "failed") || strings.Contains(lc, "no subscription") {
			return ln
		}
	}
	return ""
}

func (s *BackupService) steamAuthPath() string {
	base := filepath.Dir(s.cfg.SaveDir)
	return filepath.Join(base, "steam_auth.env")
}

func (s *BackupService) listBackups(ctx context.Context) ([]minio.ObjectInfo, error) {
	var items []minio.ObjectInfo
	for obj := range s.s3.ListObjects(ctx, s.cfg.Bucket, minio.ListObjectsOptions{Recursive: true}) {
		if obj.Err != nil {
			return nil, obj.Err
		}
		items = append(items, obj)
	}
	return items, nil
}

func (s *BackupService) createBackup(ctx context.Context) (string, error) {
	ts := time.Now().UTC().Format("20060102-150405")
	name := fmt.Sprintf("backup-%s.tar.gz", ts)

	if err := s.ensureSaveDir(); err != nil {
		return "", err
	}

	tmpFile, err := os.CreateTemp("", "enshrouded-backup-*.tar.gz")
	if err != nil {
		return "", err
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	if err := archiveDir(s.cfg.SaveDir, tmpFile); err != nil {
		return "", err
	}

	if _, err := tmpFile.Seek(0, io.SeekStart); err != nil {
		return "", err
	}

	stat, err := tmpFile.Stat()
	if err != nil {
		return "", err
	}

	_, err = s.s3.PutObject(ctx, s.cfg.Bucket, name, tmpFile, stat.Size(), minio.PutObjectOptions{ContentType: "application/gzip"})
	if err != nil {
		return "", err
	}

	go func() {
		if err := s.applyRetention(context.Background()); err != nil {
			s.logger.Printf("retention error: %v", err)
		}
	}()

	return name, nil
}

func (s *BackupService) restoreBackup(ctx context.Context, name string) error {
	if name == "" {
		return errors.New("backup name required")
	}

	if err := s.stopContainer(ctx); err != nil {
		s.logger.Printf("warn: stop container: %v", err)
	}

	tmpFile, err := os.CreateTemp("", "enshrouded-restore-*.tar.gz")
	if err != nil {
		return err
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	obj, err := s.s3.GetObject(ctx, s.cfg.Bucket, name, minio.GetObjectOptions{})
	if err != nil {
		return err
	}
	defer obj.Close()

	if _, err := io.Copy(tmpFile, obj); err != nil {
		return err
	}
	if _, err := tmpFile.Seek(0, io.SeekStart); err != nil {
		return err
	}

	if err := extractArchive(tmpFile, s.cfg.SaveDir); err != nil {
		return err
	}

	if err := s.startContainer(ctx); err != nil {
		return err
	}
	return nil
}

func (s *BackupService) uploadAndRestore(ctx context.Context, filename string, r io.Reader) error {
	tmpFile, err := os.CreateTemp("", "enshrouded-upload-*.tar")
	if err != nil {
		return err
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	if _, err := io.Copy(tmpFile, r); err != nil {
		return err
	}
	if _, err := tmpFile.Seek(0, io.SeekStart); err != nil {
		return err
	}

	if err := s.stopContainer(ctx); err != nil {
		s.logger.Printf("warn: stop container: %v", err)
	}
	if err := extractArchive(tmpFile, s.cfg.SaveDir); err != nil {
		return err
	}
	return s.startContainer(ctx)
}

func (s *BackupService) startScheduler(ctx context.Context) {
	ticker := time.NewTicker(time.Duration(s.cfg.IntervalHours) * time.Hour)
	s.logger.Printf("automatic backups every %d hour(s)", s.cfg.IntervalHours)
	for {
		select {
		case <-ticker.C:
			if _, err := s.createBackup(ctx); err != nil {
				s.logger.Printf("scheduled backup failed: %v", err)
			}
		case <-ctx.Done():
			return
		}
	}
}

func (s *BackupService) restartContainer(ctx context.Context) error {
	return s.docker.post(ctx, fmt.Sprintf("/containers/%s/restart?t=10", s.cfg.EnshroudedContainer), nil)
}

func (s *BackupService) stopContainer(ctx context.Context) error {
	return s.docker.post(ctx, fmt.Sprintf("/containers/%s/stop?t=10", s.cfg.EnshroudedContainer), nil)
}

func (s *BackupService) startContainer(ctx context.Context) error {
	return s.docker.post(ctx, fmt.Sprintf("/containers/%s/start", s.cfg.EnshroudedContainer), nil)
}

func (s *BackupService) containerStatus(ctx context.Context) (map[string]interface{}, error) {
	var inspect struct {
		ID    string `json:"Id"`
		Name  string `json:"Name"`
		State struct {
			Status  string `json:"Status"`
			Running bool   `json:"Running"`
			Health  struct {
				Status string `json:"Status"`
				Log    []struct {
					Output string `json:"Output"`
				} `json:"Log"`
			} `json:"Health"`
		} `json:"State"`
	}
	if err := s.docker.get(ctx, fmt.Sprintf("/containers/%s/json", s.cfg.EnshroudedContainer), &inspect); err != nil {
		return nil, err
	}
	status := map[string]interface{}{
		"id":      inspect.ID,
		"name":    inspect.Name,
		"state":   inspect.State.Status,
		"running": inspect.State.Running,
	}
	if inspect.State.Health.Status != "" {
		status["health"] = inspect.State.Health.Status
		status["logs"] = inspect.State.Health.Log
	}
	return status, nil
}

func (s *BackupService) applyRetention(ctx context.Context) error {
	items, err := s.listBackups(ctx)
	if err != nil {
		return err
	}
	if len(items) == 0 {
		return nil
	}

	// Sort newest first
	sort.Slice(items, func(i, j int) bool { return items[i].LastModified.After(items[j].LastModified) })

	keep := map[string]bool{}
	dailyCount := 0
	weeklyCount := 0
	monthlyCount := 0

	seenDay := map[string]bool{}
	seenWeek := map[string]bool{}
	seenMonth := map[string]bool{}

	for _, obj := range items {
		ts, err := parseTimestamp(obj.Key)
		if err != nil {
			continue
		}
		dayKey := ts.Format("2006-01-02")
		year, week := ts.ISOWeek()
		weekKey := fmt.Sprintf("%d-%02d", year, week)
		monthKey := ts.Format("2006-01")

		if dailyCount < s.cfg.RetentionDailies && !seenDay[dayKey] {
			keep[obj.Key] = true
			seenDay[dayKey] = true
			dailyCount++
			continue
		}
		if weeklyCount < s.cfg.RetentionWeeklies && !seenWeek[weekKey] {
			keep[obj.Key] = true
			seenWeek[weekKey] = true
			weeklyCount++
			continue
		}
		if monthlyCount < s.cfg.RetentionMonthlies && !seenMonth[monthKey] {
			keep[obj.Key] = true
			seenMonth[monthKey] = true
			monthlyCount++
			continue
		}
	}

	for _, obj := range items {
		if keep[obj.Key] {
			continue
		}
		s.logger.Printf("retention: deleting %s", obj.Key)
		if err := s.s3.RemoveObject(ctx, s.cfg.Bucket, obj.Key, minio.RemoveObjectOptions{}); err != nil {
			s.logger.Printf("retention delete error for %s: %v", obj.Key, err)
		}
	}
	return nil
}

func parseTimestamp(name string) (time.Time, error) {
	base := filepath.Base(name)
	base = strings.TrimSuffix(base, filepath.Ext(base))
	parts := strings.Split(base, "-")
	if len(parts) < 2 {
		return time.Time{}, errors.New("invalid name")
	}
	stamp := parts[len(parts)-1]
	if len(stamp) != len("20060102-150405") {
		// allow names with prefix like backup-20240101-120000
		if len(parts) >= 2 {
			stamp = parts[len(parts)-2] + "-" + parts[len(parts)-1]
		}
	}
	return time.Parse("20060102-150405", stamp)
}

func archiveDir(root string, w io.Writer) error {
	gz := gzip.NewWriter(w)
	defer gz.Close()
	tw := tar.NewWriter(gz)
	defer tw.Close()

	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		header.Name = rel
		if err := tw.WriteHeader(header); err != nil {
			return err
		}
		if info.Mode().IsRegular() {
			f, err := os.Open(path)
			if err != nil {
				return err
			}
			if _, err := io.Copy(tw, f); err != nil {
				f.Close()
				return err
			}
			f.Close()
		}
		return nil
	})
}

func extractArchive(r io.Reader, dest string) error {
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return err
	}
	gz, err := gzip.NewReader(r)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	base, err := filepath.Abs(dest)
	if err != nil {
		return err
	}

	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		target := filepath.Join(dest, hdr.Name)
		absTarget, err := filepath.Abs(target)
		if err != nil {
			return err
		}
		if !strings.HasPrefix(absTarget, base) {
			return fmt.Errorf("invalid path in archive: %s", hdr.Name)
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(absTarget, os.FileMode(hdr.Mode)); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(absTarget), 0o755); err != nil {
				return err
			}
			f, err := os.OpenFile(absTarget, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(hdr.Mode))
			if err != nil {
				return err
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return err
			}
			f.Close()
		default:
			continue
		}
	}
	return nil
}

func (s *BackupService) ensureSaveDir() error {
	return os.MkdirAll(s.cfg.SaveDir, 0o755)
}

func respondError(w http.ResponseWriter, status int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	fmt.Fprintf(w, `{"error":"%s"}`+"\n", sanitizeError(err))
}

func respondJSON(w http.ResponseWriter, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(true)
	_ = enc.Encode(payload)
}

func sanitizeError(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	return strings.ReplaceAll(msg, "\n", " ")
}

func decodeJSON(r *http.Request, out interface{}) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(out)
}

type dockerClient struct {
	http *http.Client
}

func newDockerClient(socket string) *dockerClient {
	if socket == "" {
		socket = "/var/run/docker.sock"
	}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			d := net.Dialer{}
			return d.DialContext(ctx, "unix", socket)
		},
	}
	return &dockerClient{
		http: &http.Client{Transport: transport},
	}
}

func (d *dockerClient) post(ctx context.Context, path string, body io.Reader) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://unix"+path, body)
	if err != nil {
		return err
	}
	resp, err := d.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("docker %s: %s", path, strings.TrimSpace(string(msg)))
	}
	return nil
}

func (d *dockerClient) get(ctx context.Context, path string, out interface{}) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://unix"+path, nil)
	if err != nil {
		return err
	}
	resp, err := d.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("docker %s: %s", path, strings.TrimSpace(string(msg)))
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
