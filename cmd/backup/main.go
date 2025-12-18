package main

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
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
	"path"
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

func parseBoolValue(val string) bool {
	switch strings.ToLower(strings.TrimSpace(val)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func uniqueValues(m map[string]string) bool {
	seen := make(map[string]struct{}, len(m))
	for _, v := range m {
		if _, ok := seen[v]; ok {
			return false
		}
		seen[v] = struct{}{}
	}
	return true
}

func asString(v interface{}) string {
	switch t := v.(type) {
	case string:
		return t
	case fmt.Stringer:
		return t.String()
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case json.Number:
		return t.String()
	default:
		return ""
	}
}

func asBool(v interface{}) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return parseBoolValue(t)
	}
	return false
}

func asInt(v interface{}) int {
	switch t := v.(type) {
	case int:
		return t
	case int64:
		return int(t)
	case float64:
		return int(t)
	case json.Number:
		if i, err := t.Int64(); err == nil {
			return int(i)
		}
	}
	return 0
}

func asInt64(v interface{}) int64 {
	switch t := v.(type) {
	case int64:
		return t
	case int:
		return int64(t)
	case float64:
		return int64(t)
	case json.Number:
		if i, err := t.Int64(); err == nil {
			return i
		}
	}
	return 0
}

func asStringSlice(v interface{}) []string {
	switch t := v.(type) {
	case []string:
		return t
	case []interface{}:
		out := make([]string, 0, len(t))
		for _, item := range t {
			s := strings.TrimSpace(asString(item))
			if s != "" {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
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
	r.HandleFunc("/backups/download", svc.handleDownloadBackup).Methods(http.MethodGet)
	r.HandleFunc("/backups/contents", svc.handleBackupContents).Methods(http.MethodGet)
	r.HandleFunc("/backup", svc.handleCreateBackup).Methods(http.MethodPost)
	r.HandleFunc("/restore", svc.handleRestoreBackup).Methods(http.MethodPost)
	r.HandleFunc("/upload", svc.handleUploadRestore).Methods(http.MethodPost)
	r.HandleFunc("/logs", svc.handleLogs).Methods(http.MethodGet)
	r.HandleFunc("/server/restart", svc.handleRestartServer).Methods(http.MethodPost)
	r.HandleFunc("/server/update", svc.handleUpdateServer).Methods(http.MethodPost)
	r.HandleFunc("/server/groups", svc.handleUpdateGroupPasswords).Methods(http.MethodPost)
	r.HandleFunc("/server/config", svc.handleGetServerConfig).Methods(http.MethodGet)
	r.HandleFunc("/server/config", svc.handleUpdateServerConfig).Methods(http.MethodPost)
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

func (s *BackupService) handleDownloadBackup(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if !isSafeBackupName(name) {
		respondError(w, http.StatusBadRequest, errors.New("invalid backup name"))
		return
	}
	obj, err := s.s3.GetObject(r.Context(), s.cfg.Bucket, name, minio.GetObjectOptions{})
	if err != nil {
		respondError(w, http.StatusInternalServerError, err)
		return
	}
	defer obj.Close()
	stat, err := obj.Stat()
	if err != nil {
		respondError(w, http.StatusNotFound, err)
		return
	}
	contentType := "application/octet-stream"
	lower := strings.ToLower(name)
	if strings.HasSuffix(lower, ".tar.gz") || strings.HasSuffix(lower, ".tgz") {
		contentType = "application/gzip"
	} else if strings.HasSuffix(lower, ".zip") {
		contentType = "application/zip"
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filepath.Base(name)))
	w.Header().Set("Content-Length", strconv.FormatInt(stat.Size, 10))
	if _, err := io.Copy(w, obj); err != nil {
		s.logger.Printf("download error for %s: %v", name, err)
	}
}

func (s *BackupService) handleBackupContents(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if !isSafeBackupName(name) {
		respondError(w, http.StatusBadRequest, errors.New("invalid backup name"))
		return
	}
	items, err := s.listBackupContents(r.Context(), name)
	if err != nil {
		respondError(w, http.StatusInternalServerError, err)
		return
	}
	respondJSON(w, map[string]interface{}{
		"name":  name,
		"items": items,
	})
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
		Name         string `json:"name"`
		BackupBefore bool   `json:"backup_before"`
	}
	var p payload
	if err := decodeJSON(r, &p); err != nil || p.Name == "" {
		respondError(w, http.StatusBadRequest, errors.New("name required"))
		return
	}
	if err := s.restoreBackup(ctx, p.Name, p.BackupBefore); err != nil {
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
	backupBefore := parseBoolValue(r.FormValue("backup_before"))
	file, header, err := r.FormFile("file")
	if err != nil {
		respondError(w, http.StatusBadRequest, errors.New("file field required"))
		return
	}
	defer file.Close()
	if err := s.uploadAndRestore(ctx, header.Filename, file, backupBefore); err != nil {
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

func (s *BackupService) handleUpdateGroupPasswords(w http.ResponseWriter, r *http.Request) {
	type payload struct {
		Admin   *string `json:"admin"`
		Friend  *string `json:"friend"`
		Guest   *string `json:"guest"`
		Visitor *string `json:"visitor"`
	}
	var p payload
	if err := decodeJSON(r, &p); err != nil {
		respondError(w, http.StatusBadRequest, fmt.Errorf("invalid payload: %w", err))
		return
	}
	updates := map[string]string{}
	addUpdate := func(key string, val *string) {
		if val == nil {
			return
		}
		v := strings.TrimSpace(*val)
		if v == "" {
			return
		}
		updates[key] = v
	}
	addUpdate("admin", p.Admin)
	addUpdate("friend", p.Friend)
	addUpdate("guest", p.Guest)
	addUpdate("visitor", p.Visitor)
	if len(updates) == 0 {
		respondError(w, http.StatusBadRequest, errors.New("no group passwords provided"))
		return
	}
	if !uniqueValues(updates) {
		respondError(w, http.StatusBadRequest, errors.New("group passwords must be unique"))
		return
	}

	if err := s.stopContainer(r.Context()); err != nil {
		s.logger.Printf("warn: stop container: %v", err)
	}
	if err := s.updateGroupPasswords(updates); err != nil {
		_ = s.startContainer(r.Context())
		respondError(w, http.StatusInternalServerError, err)
		return
	}
	if err := s.startContainer(r.Context()); err != nil {
		respondError(w, http.StatusInternalServerError, err)
		return
	}
	respondJSON(w, map[string]string{"status": "updated"})
}

type serverConfigView struct {
	Name               string   `json:"name"`
	SlotCount          int      `json:"slot_count"`
	Tags               []string `json:"tags"`
	VoiceChatMode      string   `json:"voice_chat_mode"`
	EnableVoiceChat    bool     `json:"enable_voice_chat"`
	EnableTextChat     bool     `json:"enable_text_chat"`
	GameSettingsPreset string   `json:"game_settings_preset"`
	DayTimeMinutes     int      `json:"day_time_minutes"`
	NightTimeMinutes   int      `json:"night_time_minutes"`
	ServerPassword     string   `json:"server_password"`
}

type serverConfigPayload struct {
	Name               *string  `json:"name"`
	SlotCount          *int     `json:"slot_count"`
	Tags               []string `json:"tags"`
	VoiceChatMode      *string  `json:"voice_chat_mode"`
	EnableVoiceChat    *bool    `json:"enable_voice_chat"`
	EnableTextChat     *bool    `json:"enable_text_chat"`
	GameSettingsPreset *string  `json:"game_settings_preset"`
	DayTimeMinutes     *int     `json:"day_time_minutes"`
	NightTimeMinutes   *int     `json:"night_time_minutes"`
	ServerPassword     *string  `json:"server_password"`
}

func (s *BackupService) handleGetServerConfig(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.readServerConfig()
	if err != nil {
		respondError(w, http.StatusInternalServerError, err)
		return
	}
	respondJSON(w, cfg)
}

func (s *BackupService) handleUpdateServerConfig(w http.ResponseWriter, r *http.Request) {
	var p serverConfigPayload
	if err := decodeJSON(r, &p); err != nil {
		respondError(w, http.StatusBadRequest, fmt.Errorf("invalid payload: %w", err))
		return
	}
	if err := s.updateServerConfig(&p); err != nil {
		respondError(w, http.StatusInternalServerError, err)
		return
	}
	if err := s.restartContainer(r.Context()); err != nil {
		respondError(w, http.StatusInternalServerError, err)
		return
	}
	respondJSON(w, map[string]string{"status": "updated"})
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
	Mode      string `json:"mode"`      // anonymous | user | unset
	Username  string `json:"username"`  // optional
	HasCreds  bool   `json:"has_creds"` // true if username/password present
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

func (s *BackupService) listBackupContents(ctx context.Context, name string) ([]string, error) {
	obj, err := s.s3.GetObject(ctx, s.cfg.Bucket, name, minio.GetObjectOptions{})
	if err != nil {
		return nil, err
	}
	defer obj.Close()
	if _, err := obj.Stat(); err != nil {
		return nil, err
	}
	tmpFile, err := os.CreateTemp("", "enshrouded-contents-*")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()
	if _, err := io.Copy(tmpFile, obj); err != nil {
		return nil, err
	}
	return listArchiveContents(tmpFile.Name(), 200)
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

func (s *BackupService) restoreBackup(ctx context.Context, name string, backupBefore bool) error {
	if name == "" {
		return errors.New("backup name required")
	}

	if err := s.stopContainer(ctx); err != nil {
		s.logger.Printf("warn: stop container: %v", err)
	}
	if backupBefore {
		if _, err := s.createBackup(ctx); err != nil {
			_ = s.startContainer(ctx)
			return err
		}
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

	if err := extractArchive(tmpFile.Name(), s.cfg.SaveDir); err != nil {
		return err
	}

	if err := s.startContainer(ctx); err != nil {
		return err
	}
	return nil
}

func (s *BackupService) uploadAndRestore(ctx context.Context, filename string, r io.Reader, backupBefore bool) error {
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
	if backupBefore {
		if _, err := s.createBackup(ctx); err != nil {
			_ = s.startContainer(ctx)
			return err
		}
	}
	if err := extractArchive(tmpFile.Name(), s.cfg.SaveDir); err != nil {
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

func isSafeBackupName(name string) bool {
	if name == "" {
		return false
	}
	if strings.Contains(name, "/") || strings.Contains(name, "\\") {
		return false
	}
	lower := strings.ToLower(name)
	if !(strings.HasSuffix(lower, ".tar.gz") || strings.HasSuffix(lower, ".tgz") || strings.HasSuffix(lower, ".zip")) {
		return false
	}
	return filepath.Base(name) == name
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

type archiveFormat int

const (
	archiveUnknown archiveFormat = iota
	archiveTarGz
	archiveZip
)

func extractArchive(path, dest string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	format, err := detectArchiveFormat(f)
	if err != nil {
		return err
	}
	switch format {
	case archiveTarGz:
		return extractTarGz(f, dest)
	case archiveZip:
		return extractZip(f, dest)
	default:
		return errors.New("unsupported archive format")
	}
}

func detectArchiveFormat(f *os.File) (archiveFormat, error) {
	header := make([]byte, 4)
	n, err := f.Read(header)
	if err != nil && !errors.Is(err, io.EOF) {
		return archiveUnknown, err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return archiveUnknown, err
	}
	if n >= 2 && header[0] == 0x1f && header[1] == 0x8b {
		return archiveTarGz, nil
	}
	if n >= 4 && header[0] == 'P' && header[1] == 'K' {
		return archiveZip, nil
	}
	return archiveUnknown, nil
}

func extractTarGz(r io.Reader, dest string) error {
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
		name, ok := cleanArchivePath(hdr.Name)
		if !ok {
			return fmt.Errorf("invalid path in archive: %s", hdr.Name)
		}
		target := filepath.Join(dest, name)
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

func extractZip(f *os.File, dest string) error {
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return err
	}
	stat, err := f.Stat()
	if err != nil {
		return err
	}
	zr, err := zip.NewReader(f, stat.Size())
	if err != nil {
		return err
	}
	base, err := filepath.Abs(dest)
	if err != nil {
		return err
	}
	for _, zf := range zr.File {
		name, ok := cleanArchivePath(zf.Name)
		if !ok {
			return fmt.Errorf("invalid path in archive: %s", zf.Name)
		}
		target := filepath.Join(dest, name)
		absTarget, err := filepath.Abs(target)
		if err != nil {
			return err
		}
		if !strings.HasPrefix(absTarget, base) {
			return fmt.Errorf("invalid path in archive: %s", zf.Name)
		}
		if zf.FileInfo().IsDir() {
			if err := os.MkdirAll(absTarget, 0o755); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(absTarget), 0o755); err != nil {
			return err
		}
		rc, err := zf.Open()
		if err != nil {
			return err
		}
		fh, err := os.OpenFile(absTarget, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, zf.Mode())
		if err != nil {
			rc.Close()
			return err
		}
		if _, err := io.Copy(fh, rc); err != nil {
			fh.Close()
			rc.Close()
			return err
		}
		fh.Close()
		rc.Close()
	}
	return nil
}

func listArchiveContents(path string, limit int) ([]string, error) {
	if limit <= 0 {
		limit = 200
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	format, err := detectArchiveFormat(f)
	if err != nil {
		return nil, err
	}
	switch format {
	case archiveTarGz:
		return listTarGzContents(f, limit)
	case archiveZip:
		return listZipContents(f, limit)
	default:
		return nil, errors.New("unsupported archive format")
	}
}

func listTarGzContents(r io.Reader, limit int) ([]string, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	var items []string
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		name, ok := cleanArchivePath(hdr.Name)
		if !ok {
			continue
		}
		items = append(items, name)
		if len(items) >= limit {
			break
		}
	}
	return items, nil
}

func listZipContents(f *os.File, limit int) ([]string, error) {
	stat, err := f.Stat()
	if err != nil {
		return nil, err
	}
	zr, err := zip.NewReader(f, stat.Size())
	if err != nil {
		return nil, err
	}
	items := make([]string, 0, min(limit, len(zr.File)))
	for _, zf := range zr.File {
		if zf.FileInfo().IsDir() {
			continue
		}
		name, ok := cleanArchivePath(zf.Name)
		if !ok {
			continue
		}
		items = append(items, name)
		if len(items) >= limit {
			break
		}
	}
	return items, nil
}

func cleanArchivePath(name string) (string, bool) {
	name = strings.ReplaceAll(name, "\\", "/")
	name = path.Clean("/" + name)
	name = strings.TrimPrefix(name, "/")
	if name == "" || strings.HasPrefix(name, "..") {
		return "", false
	}
	return name, true
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (s *BackupService) ensureSaveDir() error {
	return os.MkdirAll(s.cfg.SaveDir, 0o755)
}

func (s *BackupService) updateGroupPasswords(updates map[string]string) error {
	cfgPath := filepath.Clean(filepath.Join(s.cfg.SaveDir, "..", "server", "enshrouded_server.json"))
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		return err
	}
	var doc map[string]interface{}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return err
	}
	groups, ok := doc["userGroups"].([]interface{})
	if !ok {
		return errors.New("userGroups not found in server config")
	}
	updated := 0
	for _, g := range groups {
		group, ok := g.(map[string]interface{})
		if !ok {
			continue
		}
		name, _ := group["name"].(string)
		if name == "" {
			continue
		}
		key := strings.ToLower(name)
		if val, ok := updates[key]; ok {
			group["password"] = val
			updated++
		}
	}
	if updated == 0 {
		return errors.New("no matching groups found to update")
	}
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(cfgPath), "enshrouded-server-*.json")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(out); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chown(1000, 1000); err != nil {
		// Best-effort; continue even if chown fails.
		s.logger.Printf("warn: chown server config: %v", err)
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), cfgPath)
}

func (s *BackupService) serverConfigPath() string {
	return filepath.Clean(filepath.Join(s.cfg.SaveDir, "..", "server", "enshrouded_server.json"))
}

func (s *BackupService) serverConfigTxtPath() string {
	return filepath.Clean(filepath.Join(s.cfg.SaveDir, "..", "server", "server_config.txt"))
}

func (s *BackupService) readServerConfig() (*serverConfigView, error) {
	cfgPath := s.serverConfigPath()
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		if os.IsNotExist(err) {
			return &serverConfigView{
				Name:               getenv("SERVER_NAME", "Enshrouded Server"),
				SlotCount:          atoiEnv("MAX_PLAYERS", 16),
				GameSettingsPreset: "Default",
			}, nil
		}
		return nil, err
	}
	var doc map[string]interface{}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	view := &serverConfigView{
		Name:               asString(doc["name"]),
		SlotCount:          asInt(doc["slotCount"]),
		Tags:               asStringSlice(doc["tags"]),
		VoiceChatMode:      asString(doc["voiceChatMode"]),
		EnableVoiceChat:    asBool(doc["enableVoiceChat"]),
		EnableTextChat:     asBool(doc["enableTextChat"]),
		GameSettingsPreset: asString(doc["gameSettingsPreset"]),
	}
	if gs, ok := doc["gameSettings"].(map[string]interface{}); ok {
		if v := asInt64(gs["dayTimeDuration"]); v > 0 {
			view.DayTimeMinutes = int(v / int64(time.Minute))
		}
		if v := asInt64(gs["nightTimeDuration"]); v > 0 {
			view.NightTimeMinutes = int(v / int64(time.Minute))
		}
	}
	if groups, ok := doc["userGroups"].([]interface{}); ok {
		for _, g := range groups {
			group, ok := g.(map[string]interface{})
			if !ok {
				continue
			}
			name := strings.ToLower(asString(group["name"]))
			if name == "friend" {
				view.ServerPassword = asString(group["password"])
			}
		}
	}
	return view, nil
}

func clampInt(val, minVal, maxVal int) int {
	if val < minVal {
		return minVal
	}
	if val > maxVal {
		return maxVal
	}
	return val
}

func cleanTags(tags []string) []string {
	out := make([]string, 0, len(tags))
	for _, tag := range tags {
		t := strings.TrimSpace(tag)
		if t != "" {
			out = append(out, t)
		}
	}
	return out
}

func (s *BackupService) updateServerConfig(p *serverConfigPayload) error {
	cfgPath := s.serverConfigPath()
	raw, err := os.ReadFile(cfgPath)
	var doc map[string]interface{}
	if err != nil {
		if os.IsNotExist(err) {
			doc = s.defaultServerConfigDocument()
		} else {
			return err
		}
	} else {
		if err := json.Unmarshal(raw, &doc); err != nil {
			return err
		}
	}

	txtUpdates := map[string]string{}

	if p.Name != nil {
		name := strings.TrimSpace(*p.Name)
		doc["name"] = name
		txtUpdates["SERVER_NAME"] = name
	}
	if p.SlotCount != nil {
		slot := clampInt(*p.SlotCount, 1, 32)
		doc["slotCount"] = slot
		txtUpdates["MAX_PLAYERS"] = strconv.Itoa(slot)
	}
	if p.Tags != nil {
		doc["tags"] = cleanTags(p.Tags)
	}
	if p.VoiceChatMode != nil {
		mode := strings.TrimSpace(*p.VoiceChatMode)
		if mode != "" && mode != "Proximity" && mode != "Global" {
			return fmt.Errorf("invalid voice chat mode")
		}
		if mode != "" {
			doc["voiceChatMode"] = mode
		}
	}
	if p.EnableVoiceChat != nil {
		doc["enableVoiceChat"] = *p.EnableVoiceChat
	}
	if p.EnableTextChat != nil {
		doc["enableTextChat"] = *p.EnableTextChat
	}
	if p.GameSettingsPreset != nil {
		preset := strings.TrimSpace(*p.GameSettingsPreset)
		if preset != "" {
			doc["gameSettingsPreset"] = preset
		}
	}
	gs, ok := doc["gameSettings"].(map[string]interface{})
	if !ok || gs == nil {
		gs = map[string]interface{}{}
		doc["gameSettings"] = gs
	}
	if p.DayTimeMinutes != nil && *p.DayTimeMinutes > 0 {
		gs["dayTimeDuration"] = int64(*p.DayTimeMinutes) * int64(time.Minute)
	}
	if p.NightTimeMinutes != nil && *p.NightTimeMinutes > 0 {
		gs["nightTimeDuration"] = int64(*p.NightTimeMinutes) * int64(time.Minute)
	}

	if p.ServerPassword != nil {
		newPass := strings.TrimSpace(*p.ServerPassword)
		if groups, ok := doc["userGroups"].([]interface{}); ok {
			friendFound := false
			for _, g := range groups {
				group, ok := g.(map[string]interface{})
				if !ok {
					continue
				}
				name := strings.ToLower(asString(group["name"]))
				pass := strings.TrimSpace(asString(group["password"]))
				if name != "friend" && newPass != "" && pass != "" && newPass == pass {
					return errors.New("group passwords must be unique")
				}
				if name == "friend" {
					group["password"] = newPass
					friendFound = true
				}
			}
			if !friendFound {
				doc["userGroups"] = append(groups, map[string]interface{}{
					"name":                 "Friend",
					"password":             newPass,
					"canKickBan":           false,
					"canAccessInventories": true,
					"canEditWorld":         true,
					"canEditBase":          true,
					"canExtendBase":        false,
					"reservedSlots":        0,
				})
			}
		} else {
			doc["userGroups"] = []interface{}{
				map[string]interface{}{
					"name":                 "Friend",
					"password":             newPass,
					"canKickBan":           false,
					"canAccessInventories": true,
					"canEditWorld":         true,
					"canEditBase":          true,
					"canExtendBase":        false,
					"reservedSlots":        0,
				},
			}
		}
		txtUpdates["SERVER_PASSWORD"] = newPass
	}

	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	if err := s.writeAtomic(cfgPath, out); err != nil {
		return err
	}
	if len(txtUpdates) > 0 {
		if err := s.updateServerConfigTxt(txtUpdates); err != nil {
			return err
		}
	}
	return nil
}

func (s *BackupService) defaultServerConfigDocument() map[string]interface{} {
	return map[string]interface{}{
		"name":               getenv("SERVER_NAME", "Enshrouded Server"),
		"saveDirectory":      s.cfg.SaveDir,
		"logDirectory":       "./logs",
		"ip":                 "0.0.0.0",
		"queryPort":          atoiEnv("QUERY_PORT", 15637),
		"slotCount":          atoiEnv("MAX_PLAYERS", 16),
		"tags":               []string{},
		"voiceChatMode":      "Proximity",
		"enableVoiceChat":    true,
		"enableTextChat":     true,
		"gameSettingsPreset": "Default",
		"gameSettings": map[string]interface{}{
			"dayTimeDuration":   int64(30) * int64(time.Minute),
			"nightTimeDuration": int64(12) * int64(time.Minute),
		},
		"userGroups": []interface{}{
			map[string]interface{}{"name": "Admin", "password": "", "canKickBan": true, "canAccessInventories": true, "canEditWorld": true, "canEditBase": true, "canExtendBase": true, "reservedSlots": 0},
			map[string]interface{}{"name": "Friend", "password": "", "canKickBan": false, "canAccessInventories": true, "canEditWorld": true, "canEditBase": true, "canExtendBase": false, "reservedSlots": 0},
			map[string]interface{}{"name": "Guest", "password": "", "canKickBan": false, "canAccessInventories": false, "canEditWorld": true, "canEditBase": false, "canExtendBase": false, "reservedSlots": 0},
			map[string]interface{}{"name": "Visitor", "password": "", "canKickBan": false, "canAccessInventories": false, "canEditWorld": false, "canEditBase": false, "canExtendBase": false, "reservedSlots": 0},
		},
		"bannedAccounts": []interface{}{},
	}
}

func (s *BackupService) updateServerConfigTxt(updates map[string]string) error {
	cfgPath := s.serverConfigTxtPath()
	current := map[string]string{
		"SERVER_NAME":     getenv("SERVER_NAME", "Enshrouded Server"),
		"SERVER_PASSWORD": getenv("SERVER_PASSWORD", ""),
		"MAX_PLAYERS":     getenv("MAX_PLAYERS", "16"),
		"GAME_PORT":       getenv("GAME_PORT", "15636"),
		"QUERY_PORT":      getenv("QUERY_PORT", "15637"),
		"SAVE_DIR":        getenv("SAVE_DIR", "/data/savegame"),
	}
	if raw, err := os.ReadFile(cfgPath); err == nil {
		sc := bufio.NewScanner(bytes.NewReader(raw))
		for sc.Scan() {
			line := sc.Text()
			parts := strings.SplitN(line, "=", 2)
			if len(parts) != 2 {
				continue
			}
			key := strings.TrimSpace(parts[0])
			val := parts[1]
			if key == "" {
				continue
			}
			current[key] = val
		}
	}
	for k, v := range updates {
		current[k] = v
	}

	keys := []string{"SERVER_NAME", "SERVER_PASSWORD", "MAX_PLAYERS", "GAME_PORT", "QUERY_PORT", "SAVE_DIR"}
	var buf bytes.Buffer
	for _, k := range keys {
		if v, ok := current[k]; ok {
			buf.WriteString(fmt.Sprintf("%s=%s\n", k, v))
		}
	}
	return s.writeAtomic(cfgPath, buf.Bytes())
}

func (s *BackupService) writeAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "enshrouded-config-*")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chown(1000, 1000); err != nil {
		s.logger.Printf("warn: chown %s: %v", filepath.Base(path), err)
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
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
