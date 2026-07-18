package main

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// Config holds env-driven configuration.
type Config struct {
	SaveDir             string
	ServerConfigPath    string
	ServerConfigTxtPath string
	LogDir              string
	SteamAuthFile       string
	SteamAppManifest    string
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
	MaxExtractFiles     int
	MaxExtractBytes     int64
	HealthTimeout       time.Duration
	InternalToken       string
	DockerToken         string
	AllowInsecure       bool
	AuditPath           string
	WebhookURL          string
	A2SAddr             string
	A2STimeout          time.Duration
	RestartRequireEmpty bool
	MaintenanceWindow   string
	PlayerNotifications bool
	PlayerPollInterval  time.Duration
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

func atoi64Env(key string, def int64) int64 {
	if v := os.Getenv(key); v != "" {
		if i, err := strconv.ParseInt(v, 10, 64); err == nil {
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
	cfg         Config
	s3          *minio.Client
	docker      *dockerClient
	logger      *log.Logger
	operationMu sync.Mutex
	jobs        *jobManager
	startedAt   time.Time
}

func main() {
	endpoint := getenv("BACKUP_S3_ENDPOINT", "http://minio:9000")
	useSSL := parseBoolEnv("BACKUP_S3_SSL", strings.HasPrefix(endpoint, "https://"))
	endpoint = strings.TrimPrefix(strings.TrimPrefix(endpoint, "https://"), "http://")

	cfg := Config{
		SaveDir:             getenv("BACKUP_SAVE_DIR", "/data/savegame"),
		ServerConfigPath:    getenv("BACKUP_SERVER_CONFIG_PATH", "/data/server/enshrouded_server.json"),
		ServerConfigTxtPath: getenv("BACKUP_SERVER_CONFIG_TXT_PATH", "/data/server/server_config.txt"),
		LogDir:              getenv("BACKUP_LOG_DIR", "/data/server/logs"),
		SteamAuthFile:       getenv("BACKUP_STEAM_AUTH_FILE", "/data/steam_auth.env"),
		SteamAppManifest:    getenv("BACKUP_STEAM_APP_MANIFEST", "/data/server/steamapps/appmanifest_2278520.acf"),
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
		MaxExtractFiles:     atoiEnv("BACKUP_MAX_EXTRACT_FILES", 10000),
		MaxExtractBytes:     atoi64Env("BACKUP_MAX_EXTRACT_BYTES", 4<<30),
		HealthTimeout:       time.Duration(atoiEnv("BACKUP_HEALTH_TIMEOUT_SECONDS", 900)) * time.Second,
		InternalToken:       getenv("BACKUP_INTERNAL_TOKEN", ""),
		DockerToken:         getenv("DOCKER_CONTROLLER_TOKEN", ""),
		AllowInsecure:       parseBoolEnv("ALLOW_INSECURE_DEFAULTS", false),
		AuditPath:           getenv("BACKUP_AUDIT_PATH", "/data/control/audit.jsonl"),
		WebhookURL:          getenv("BACKUP_NOTIFICATION_WEBHOOK_URL", ""),
		A2SAddr:             getenv("BACKUP_A2S_ADDR", "enshrouded:15637"),
		A2STimeout:          time.Duration(atoiEnv("BACKUP_A2S_TIMEOUT_MS", 2000)) * time.Millisecond,
		RestartRequireEmpty: parseBoolEnv("BACKUP_RESTART_REQUIRE_EMPTY", false),
		MaintenanceWindow:   getenv("BACKUP_MAINTENANCE_WINDOW", ""),
		PlayerNotifications: parseBoolEnv("BACKUP_PLAYER_NOTIFICATIONS", false),
		PlayerPollInterval:  time.Duration(atoiEnv("BACKUP_PLAYER_POLL_SECONDS", 60)) * time.Second,
	}

	logger := log.New(os.Stdout, "backup ", log.LstdFlags|log.Lmsgprefix)
	if err := validateBackupConfig(cfg); err != nil {
		logger.Fatalf("invalid backup configuration: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	s3Client, err := minio.New(cfg.Endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.AccessKey, cfg.SecretKey, ""),
		Secure: cfg.UseSSL,
	})
	if err != nil {
		logger.Fatalf("minio init: %v", err)
	}

	dockerClient := newDockerClient(getenv("DOCKER_HOST", "/var/run/docker.sock"), cfg.DockerToken)

	svc := &BackupService{cfg: cfg, s3: s3Client, docker: dockerClient, logger: logger, startedAt: time.Now().UTC()}
	svc.jobs = newJobManager(ctx, logger, cfg.AuditPath, cfg.WebhookURL)

	if err := svc.ensureBucket(ctx); err != nil {
		logger.Printf("warn: unable to verify bucket %s: %v", cfg.Bucket, err)
	}

	if cfg.IntervalHours > 0 {
		go svc.startScheduler(ctx)
	}
	if cfg.PlayerNotifications && cfg.WebhookURL != "" {
		go svc.startPlayerMonitor(ctx)
	}

	r := mux.NewRouter()
	r.HandleFunc("/health", svc.handleHealth).Methods(http.MethodGet)
	r.HandleFunc("/ready", svc.handleReady).Methods(http.MethodGet)
	r.HandleFunc("/backups", svc.handleListBackups).Methods(http.MethodGet)
	r.HandleFunc("/backups/download", svc.handleDownloadBackup).Methods(http.MethodGet)
	r.HandleFunc("/backups/contents", svc.handleBackupContents).Methods(http.MethodGet)
	r.HandleFunc("/backups/preview", svc.handleBackupPreview).Methods(http.MethodGet)
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
	r.HandleFunc("/jobs", svc.handleListJobs).Methods(http.MethodGet)
	r.HandleFunc("/jobs/{id}", svc.handleGetJob).Methods(http.MethodGet)
	r.HandleFunc("/operations/status", svc.handleOperationsStatus).Methods(http.MethodGet)
	r.HandleFunc("/diagnostics", svc.handleDiagnostics).Methods(http.MethodGet)
	r.HandleFunc("/metrics", svc.handleMetrics).Methods(http.MethodGet)

	httpServer := &http.Server{
		Addr:              cfg.BindAddr,
		Handler:           svc.requireInternalToken(r),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Minute,
		WriteTimeout:      15 * time.Minute,
		IdleTimeout:       60 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			logger.Printf("http shutdown error: %v", err)
		}
	}()

	logger.Printf("listening on %s", cfg.BindAddr)
	if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
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

func (s *BackupService) handleListJobs(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, s.jobs.list(atoiQuery(r, "limit", 20)))
}

func (s *BackupService) handleGetJob(w http.ResponseWriter, r *http.Request) {
	item, ok := s.jobs.get(mux.Vars(r)["id"])
	if !ok {
		respondError(w, http.StatusNotFound, errors.New("job not found"))
		return
	}
	respondJSON(w, item)
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
	item, err := s.jobs.enqueue("backup", "ui", func(ctx context.Context) (map[string]interface{}, error) {
		name, err := s.createBackup(ctx)
		if err != nil {
			return nil, err
		}
		return map[string]interface{}{"name": name}, nil
	})
	if err != nil {
		respondError(w, http.StatusInternalServerError, err)
		return
	}
	respondJSONStatus(w, http.StatusAccepted, item)
}

func (s *BackupService) handleRestoreBackup(w http.ResponseWriter, r *http.Request) {
	type payload struct {
		Name         string `json:"name"`
		BackupBefore bool   `json:"backup_before"`
	}
	var p payload
	if err := decodeJSON(r, &p); err != nil || p.Name == "" {
		respondError(w, http.StatusBadRequest, errors.New("name required"))
		return
	}
	item, err := s.jobs.enqueue("restore", "ui", func(ctx context.Context) (map[string]interface{}, error) {
		if err := s.restoreBackup(ctx, p.Name, p.BackupBefore); err != nil {
			return nil, err
		}
		return map[string]interface{}{"restored": p.Name}, nil
	})
	if err != nil {
		respondError(w, http.StatusInternalServerError, err)
		return
	}
	respondJSONStatus(w, http.StatusAccepted, item)
}

func (s *BackupService) handleUploadRestore(w http.ResponseWriter, r *http.Request) {
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
	uploadDir := filepath.Join(filepath.Dir(s.cfg.AuditPath), "uploads")
	if err := os.MkdirAll(uploadDir, 0o700); err != nil {
		respondError(w, http.StatusInternalServerError, err)
		return
	}
	staged, err := os.CreateTemp(uploadDir, "restore-upload-*")
	if err != nil {
		respondError(w, http.StatusInternalServerError, err)
		return
	}
	stagedPath := staged.Name()
	if _, err := io.Copy(staged, file); err != nil {
		staged.Close()
		_ = os.Remove(stagedPath)
		respondError(w, http.StatusInternalServerError, err)
		return
	}
	if err := staged.Close(); err != nil {
		_ = os.Remove(stagedPath)
		respondError(w, http.StatusInternalServerError, err)
		return
	}
	filename := filepath.Base(header.Filename)
	item, err := s.jobs.enqueue("upload_restore", "ui", func(ctx context.Context) (map[string]interface{}, error) {
		defer os.Remove(stagedPath)
		input, err := os.Open(stagedPath)
		if err != nil {
			return nil, err
		}
		defer input.Close()
		if err := s.uploadAndRestore(ctx, filename, input, backupBefore); err != nil {
			return nil, err
		}
		return map[string]interface{}{"restored": filename}, nil
	})
	if err != nil {
		_ = os.Remove(stagedPath)
		respondError(w, http.StatusInternalServerError, err)
		return
	}
	respondJSONStatus(w, http.StatusAccepted, item)
}

func (s *BackupService) handleLogs(w http.ResponseWriter, r *http.Request) {
	logDir := s.cfg.LogDir
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
	item, err := s.jobs.enqueue("restart", "ui", func(ctx context.Context) (map[string]interface{}, error) {
		if err := s.checkRestartPolicy(ctx, false); err != nil {
			return nil, err
		}
		return nil, s.restartAndWait(ctx)
	})
	if err != nil {
		respondError(w, http.StatusInternalServerError, err)
		return
	}
	respondJSONStatus(w, http.StatusAccepted, item)
}

func (s *BackupService) handleUpdateServer(w http.ResponseWriter, r *http.Request) {
	item, err := s.jobs.enqueue("update", "ui", func(ctx context.Context) (map[string]interface{}, error) {
		if err := s.checkRestartPolicy(ctx, true); err != nil {
			return nil, err
		}
		return nil, s.restartAndWait(ctx)
	})
	if err != nil {
		respondError(w, http.StatusInternalServerError, err)
		return
	}
	respondJSONStatus(w, http.StatusAccepted, item)
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

	item, err := s.jobs.enqueue("group_config", "ui", func(ctx context.Context) (map[string]interface{}, error) {
		if err := s.checkRestartPolicy(ctx, false); err != nil {
			return nil, err
		}
		if err := s.applyConfigTransaction(ctx, func() error { return s.updateGroupPasswords(updates) }); err != nil {
			return nil, err
		}
		return map[string]interface{}{"updated": true}, nil
	})
	if err != nil {
		respondError(w, http.StatusInternalServerError, err)
		return
	}
	respondJSONStatus(w, http.StatusAccepted, item)
}

type serverConfigView struct {
	Name               string                 `json:"name"`
	SlotCount          int                    `json:"slot_count"`
	Tags               []string               `json:"tags"`
	VoiceChatMode      string                 `json:"voice_chat_mode"`
	EnableVoiceChat    bool                   `json:"enable_voice_chat"`
	EnableTextChat     bool                   `json:"enable_text_chat"`
	GameSettingsPreset string                 `json:"game_settings_preset"`
	DayTimeMinutes     int                    `json:"day_time_minutes"`
	NightTimeMinutes   int                    `json:"night_time_minutes"`
	GameSettings       map[string]interface{} `json:"game_settings,omitempty"`
}

type serverConfigPayload struct {
	Name               *string           `json:"name"`
	SlotCount          *int              `json:"slot_count"`
	Tags               []string          `json:"tags"`
	VoiceChatMode      *string           `json:"voice_chat_mode"`
	EnableVoiceChat    *bool             `json:"enable_voice_chat"`
	EnableTextChat     *bool             `json:"enable_text_chat"`
	GameSettingsPreset *string           `json:"game_settings_preset"`
	DayTimeMinutes     *int              `json:"day_time_minutes"`
	NightTimeMinutes   *int              `json:"night_time_minutes"`
	ServerPassword     *string           `json:"server_password"`
	GameSettings       map[string]string `json:"game_settings"`
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
	item, err := s.jobs.enqueue("server_config", "ui", func(ctx context.Context) (map[string]interface{}, error) {
		if err := s.checkRestartPolicy(ctx, false); err != nil {
			return nil, err
		}
		if err := s.applyConfigTransaction(ctx, func() error { return s.updateServerConfig(&p) }); err != nil {
			return nil, err
		}
		return map[string]interface{}{"updated": true}, nil
	})
	if err != nil {
		respondError(w, http.StatusInternalServerError, err)
		return
	}
	respondJSONStatus(w, http.StatusAccepted, item)
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
	item, err := s.jobs.enqueue("steam_auth_restart", "ui", func(ctx context.Context) (map[string]interface{}, error) {
		if err := s.writeSteamAuthFile(p.Username, p.Password, p.GuardCode); err != nil {
			return nil, err
		}
		return map[string]interface{}{"stored": true}, s.restartAndWait(ctx)
	})
	if err != nil {
		respondError(w, http.StatusInternalServerError, err)
		return
	}
	respondJSONStatus(w, http.StatusAccepted, item)
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
	item, err := s.jobs.enqueue("steam_anonymous_restart", "ui", func(ctx context.Context) (map[string]interface{}, error) {
		if err := s.writeSteamAnonymous(); err != nil {
			return nil, err
		}
		return map[string]interface{}{"anonymous": true}, s.restartAndWait(ctx)
	})
	if err != nil {
		respondError(w, http.StatusInternalServerError, err)
		return
	}
	respondJSONStatus(w, http.StatusAccepted, item)
}

func (s *BackupService) writeSteamAuthFile(user, pass, guard string) error {
	authPath := s.steamAuthPath()
	encode := func(value string) string { return base64.StdEncoding.EncodeToString([]byte(value)) }
	content := fmt.Sprintf("STEAM_CHOSEN=1\nSTEAM_LOGIN=user\nSTEAM_USERNAME_B64=%s\nSTEAM_PASSWORD_B64=%s\n", encode(user), encode(pass))
	if strings.TrimSpace(guard) != "" {
		content += fmt.Sprintf("STEAM_GUARD_CODE_B64=%s\n", encode(guard))
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
		if strings.HasPrefix(ln, "STEAM_USERNAME_B64=") {
			if decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(strings.TrimPrefix(ln, "STEAM_USERNAME_B64="))); err == nil {
				state.Username = string(decoded)
			}
		}
		if strings.HasPrefix(ln, "STEAM_PASSWORD=") && strings.TrimSpace(strings.TrimPrefix(ln, "STEAM_PASSWORD=")) != "" {
			state.HasCreds = true
		}
		if strings.HasPrefix(ln, "STEAM_PASSWORD_B64=") && strings.TrimSpace(strings.TrimPrefix(ln, "STEAM_PASSWORD_B64=")) != "" {
			state.HasCreds = true
		}
		if strings.HasPrefix(ln, "STEAM_GUARD_CODE=") && strings.TrimSpace(strings.TrimPrefix(ln, "STEAM_GUARD_CODE=")) != "" {
			state.GuardHint = true
		}
		if strings.HasPrefix(ln, "STEAM_GUARD_CODE_B64=") && strings.TrimSpace(strings.TrimPrefix(ln, "STEAM_GUARD_CODE_B64=")) != "" {
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
	return filepath.Clean(s.cfg.SteamAuthFile)
}

func (s *BackupService) listBackups(ctx context.Context) ([]minio.ObjectInfo, error) {
	var items []minio.ObjectInfo
	for obj := range s.s3.ListObjects(ctx, s.cfg.Bucket, minio.ListObjectsOptions{Recursive: true}) {
		if obj.Err != nil {
			return nil, obj.Err
		}
		if !isSafeBackupName(obj.Key) {
			continue
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
	s.operationMu.Lock()
	defer s.operationMu.Unlock()
	return s.createBackupUnlocked(ctx)
}

func (s *BackupService) createBackupUnlocked(ctx context.Context) (string, error) {
	now := time.Now().UTC()
	ts := now.Format("20060102-150405.000000000")
	name := fmt.Sprintf("backup-%s.tar.gz", ts)

	if err := s.ensureSaveDir(); err != nil {
		return "", err
	}
	stageDir, err := s.snapshotCurrent(ctx, now)
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(stageDir)

	tmpFile, err := os.CreateTemp("", "enshrouded-backup-*.tar.gz")
	if err != nil {
		return "", err
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	if err := archiveDir(stageDir, tmpFile); err != nil {
		return "", err
	}
	if err := tmpFile.Sync(); err != nil {
		return "", err
	}

	if _, err := tmpFile.Seek(0, io.SeekStart); err != nil {
		return "", err
	}

	stat, err := tmpFile.Stat()
	if err != nil {
		return "", err
	}
	archiveSHA256, err := sha256File(tmpFile.Name())
	if err != nil {
		return "", err
	}

	opts := minio.PutObjectOptions{
		ContentType:  "application/gzip",
		UserMetadata: map[string]string{"sha256": archiveSHA256, "manifest-schema": strconv.Itoa(backupManifestSchema)},
	}
	opts.SetMatchETagExcept("*")
	upload, err := s.s3.PutObject(ctx, s.cfg.Bucket, name, tmpFile, stat.Size(), opts)
	if err != nil {
		return "", err
	}
	if upload.Size != stat.Size() {
		return "", fmt.Errorf("backup upload size mismatch: wrote %d bytes, expected %d", upload.Size, stat.Size())
	}

	if err := s.applyRetention(ctx); err != nil {
		return "", fmt.Errorf("backup uploaded but retention failed: %w", err)
	}
	stored, err := s.s3.StatObject(ctx, s.cfg.Bucket, name, minio.StatObjectOptions{})
	if err != nil {
		return "", fmt.Errorf("backup did not remain readable after retention: %w", err)
	}
	if stored.Size != stat.Size() {
		return "", fmt.Errorf("stored backup size mismatch: got %d bytes, expected %d", stored.Size, stat.Size())
	}
	if upload.ETag != "" && stored.ETag != "" && upload.ETag != stored.ETag {
		return "", fmt.Errorf("stored backup ETag mismatch: got %s, expected %s", stored.ETag, upload.ETag)
	}

	return name, nil
}

func (s *BackupService) snapshotCurrent(ctx context.Context, now time.Time) (stageDir string, err error) {
	wasRunning, err := s.containerRunning(ctx)
	if err != nil {
		return "", fmt.Errorf("inspect game container before snapshot: %w", err)
	}
	stoppedByUs := false
	if wasRunning {
		if err := s.stopContainer(ctx); err != nil {
			return "", fmt.Errorf("stop game container for snapshot: %w", err)
		}
		stoppedByUs = true
	}
	defer func() {
		if !stoppedByUs {
			return
		}
		recoveryCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if startErr := s.startContainer(recoveryCtx); startErr != nil {
			err = errors.Join(err, fmt.Errorf("restart game container after snapshot: %w", startErr))
		}
	}()

	configFiles := map[string]string{
		"enshrouded_server.json": s.serverConfigPath(),
		"server_config.txt":      s.serverConfigTxtPath(),
	}
	stageDir, err = createSnapshotStage(s.cfg.SaveDir, configFiles, readSteamBuild(s.cfg.SteamAppManifest), now)
	if err != nil {
		return "", err
	}
	if wasRunning {
		if err := s.startContainer(ctx); err != nil {
			_ = os.RemoveAll(stageDir)
			return "", fmt.Errorf("restart game container after snapshot: %w", err)
		}
		stoppedByUs = false
	}
	return stageDir, nil
}

func (s *BackupService) restoreBackup(ctx context.Context, name string, backupBefore bool) error {
	if !isSafeBackupName(name) {
		return errors.New("valid backup name required")
	}
	s.operationMu.Lock()
	defer s.operationMu.Unlock()

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

	stat, err := obj.Stat()
	if err != nil {
		return err
	}
	if _, err := io.Copy(tmpFile, obj); err != nil {
		return err
	}
	if downloaded, err := tmpFile.Stat(); err != nil {
		return err
	} else if downloaded.Size() != stat.Size {
		return fmt.Errorf("downloaded backup size mismatch: got %d bytes, expected %d", downloaded.Size(), stat.Size)
	}
	return s.restoreLocalArchive(ctx, tmpFile.Name(), backupBefore)
}

func (s *BackupService) uploadAndRestore(ctx context.Context, filename string, r io.Reader, backupBefore bool) error {
	if !isSafeBackupName(filepath.Base(filename)) {
		return errors.New("uploaded backup must be a .tar.gz, .tgz, or .zip archive")
	}
	s.operationMu.Lock()
	defer s.operationMu.Unlock()

	tmpFile, err := os.CreateTemp("", "enshrouded-upload-*.tar")
	if err != nil {
		return err
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	if _, err := io.Copy(tmpFile, r); err != nil {
		return err
	}
	return s.restoreLocalArchive(ctx, tmpFile.Name(), backupBefore)
}

func (s *BackupService) startScheduler(ctx context.Context) {
	ticker := time.NewTicker(time.Duration(s.cfg.IntervalHours) * time.Hour)
	defer ticker.Stop()
	s.logger.Printf("automatic backups every %d hour(s)", s.cfg.IntervalHours)
	for {
		select {
		case <-ticker.C:
			if _, err := s.jobs.enqueue("backup", "scheduler", func(jobCtx context.Context) (map[string]interface{}, error) {
				name, err := s.createBackup(jobCtx)
				if err != nil {
					return nil, err
				}
				return map[string]interface{}{"name": name}, nil
			}); err != nil {
				s.logger.Printf("scheduled backup enqueue failed: %v", err)
			}
		case <-ctx.Done():
			return
		}
	}
}

func (s *BackupService) restartContainer(ctx context.Context) error {
	return s.docker.post(ctx, fmt.Sprintf("/containers/%s/restart?t=10", s.cfg.EnshroudedContainer), nil)
}

func (s *BackupService) restartAndWait(ctx context.Context) error {
	if err := s.restartContainer(ctx); err != nil {
		return err
	}
	healthCtx, cancel := context.WithTimeout(ctx, s.cfg.HealthTimeout)
	defer cancel()
	return s.waitContainerHealthy(healthCtx)
}

func (s *BackupService) startAndWait(ctx context.Context) error {
	if err := s.startContainer(ctx); err != nil {
		return err
	}
	healthCtx, cancel := context.WithTimeout(ctx, s.cfg.HealthTimeout)
	defer cancel()
	return s.waitContainerHealthy(healthCtx)
}

func (s *BackupService) stopContainer(ctx context.Context) error {
	return s.docker.post(ctx, fmt.Sprintf("/containers/%s/stop?t=10", s.cfg.EnshroudedContainer), nil)
}

func (s *BackupService) startContainer(ctx context.Context) error {
	return s.docker.post(ctx, fmt.Sprintf("/containers/%s/start", s.cfg.EnshroudedContainer), nil)
}

func (s *BackupService) containerRunning(ctx context.Context) (bool, error) {
	var inspect struct {
		State struct {
			Running bool `json:"Running"`
		} `json:"State"`
	}
	if err := s.docker.get(ctx, fmt.Sprintf("/containers/%s/json", s.cfg.EnshroudedContainer), &inspect); err != nil {
		return false, err
	}
	return inspect.State.Running, nil
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

	keep := selectRetention(items, s.cfg.RetentionDailies, s.cfg.RetentionWeeklies, s.cfg.RetentionMonthlies, func(name string, err error) {
		s.logger.Printf("retention: keeping unrecognized object %s: %v", name, err)
	})

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
	lower := strings.ToLower(base)
	matchedSuffix := false
	for _, suffix := range []string{".tar.gz", ".tgz", ".zip"} {
		if strings.HasSuffix(lower, suffix) {
			base = base[:len(base)-len(suffix)]
			matchedSuffix = true
			break
		}
	}
	if !matchedSuffix {
		return time.Time{}, errors.New("unsupported backup extension")
	}
	parts := strings.Split(base, "-")
	if len(parts) < 3 {
		return time.Time{}, errors.New("invalid name")
	}
	stamp := parts[len(parts)-2] + "-" + parts[len(parts)-1]
	for _, layout := range []string{"20060102-150405.999999999", "20060102-150405"} {
		if parsed, err := time.Parse(layout, stamp); err == nil {
			return parsed, nil
		}
	}
	return time.Time{}, errors.New("invalid timestamp")
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
	tw := tar.NewWriter(gz)

	walkErr := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
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
	tarCloseErr := tw.Close()
	gzipCloseErr := gz.Close()
	return errors.Join(walkErr, tarCloseErr, gzipCloseErr)
}

type archiveFormat int

const (
	archiveUnknown archiveFormat = iota
	archiveTarGz
	archiveZip
)

type archiveLimits struct {
	MaxFiles int
	MaxBytes int64
}

func extractArchive(path, dest string) error {
	return extractArchiveWithLimits(path, dest, archiveLimits{MaxFiles: 10000, MaxBytes: 4 << 30})
}

func extractArchiveWithLimits(path, dest string, limits archiveLimits) error {
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
		return extractTarGz(f, dest, limits)
	case archiveZip:
		return extractZip(f, dest, limits)
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

func extractTarGz(r io.Reader, dest string, limits archiveLimits) error {
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
	seen := map[string]struct{}{}
	entries := 0
	var expandedBytes int64

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
		if _, exists := seen[name]; exists {
			return fmt.Errorf("duplicate path in archive: %s", hdr.Name)
		}
		seen[name] = struct{}{}
		entries++
		if limits.MaxFiles > 0 && entries > limits.MaxFiles {
			return fmt.Errorf("archive contains more than %d entries", limits.MaxFiles)
		}
		target := filepath.Join(dest, name)
		absTarget, err := filepath.Abs(target)
		if err != nil {
			return err
		}
		if !pathWithinBase(base, absTarget) {
			return fmt.Errorf("invalid path in archive: %s", hdr.Name)
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(absTarget, os.FileMode(hdr.Mode)); err != nil {
				return err
			}
		case tar.TypeReg:
			if hdr.Size < 0 || (limits.MaxBytes > 0 && hdr.Size > limits.MaxBytes-expandedBytes) {
				return fmt.Errorf("archive expands beyond %d bytes", limits.MaxBytes)
			}
			expandedBytes += hdr.Size
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
			return fmt.Errorf("unsupported archive entry type for %s", hdr.Name)
		}
	}
	return nil
}

func extractZip(f *os.File, dest string, limits archiveLimits) error {
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
	seen := map[string]struct{}{}
	entries := 0
	var expandedBytes int64
	for _, zf := range zr.File {
		name, ok := cleanArchivePath(zf.Name)
		if !ok {
			return fmt.Errorf("invalid path in archive: %s", zf.Name)
		}
		if _, exists := seen[name]; exists {
			return fmt.Errorf("duplicate path in archive: %s", zf.Name)
		}
		seen[name] = struct{}{}
		entries++
		if limits.MaxFiles > 0 && entries > limits.MaxFiles {
			return fmt.Errorf("archive contains more than %d entries", limits.MaxFiles)
		}
		target := filepath.Join(dest, name)
		absTarget, err := filepath.Abs(target)
		if err != nil {
			return err
		}
		if !pathWithinBase(base, absTarget) {
			return fmt.Errorf("invalid path in archive: %s", zf.Name)
		}
		if zf.FileInfo().IsDir() {
			if err := os.MkdirAll(absTarget, 0o755); err != nil {
				return err
			}
			continue
		}
		if !zf.Mode().IsRegular() {
			return fmt.Errorf("unsupported archive entry type for %s", zf.Name)
		}
		entrySize := int64(zf.UncompressedSize64)
		if entrySize < 0 || (limits.MaxBytes > 0 && entrySize > limits.MaxBytes-expandedBytes) {
			return fmt.Errorf("archive expands beyond %d bytes", limits.MaxBytes)
		}
		expandedBytes += entrySize
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
	if name == "" || strings.HasPrefix(name, "/") || (len(name) >= 2 && name[1] == ':') {
		return "", false
	}
	for _, part := range strings.Split(name, "/") {
		if part == ".." {
			return "", false
		}
	}
	name = path.Clean(name)
	if name == "" || name == "." || strings.HasPrefix(name, "../") || len(name) > 1024 {
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

type settingRule struct {
	kind  string
	enums []string
}

var allowedGameSettings = map[string]settingRule{
	"playerHealthFactor":                {kind: "float"},
	"playerStaminaFactor":               {kind: "float"},
	"enableDurability":                  {kind: "bool"},
	"enableStarvingDebuff":              {kind: "bool"},
	"foodBuffDurationFactor":            {kind: "float"},
	"shroudTimeFactor":                  {kind: "float"},
	"tombstoneMode":                     {kind: "enum", enums: []string{"AddBackpackMaterials", "DropBackpackMaterials"}},
	"weatherFrequency":                  {kind: "enum", enums: []string{"Low", "Normal", "High"}},
	"enemyDamageFactor":                 {kind: "float"},
	"enemyHealthFactor":                 {kind: "float"},
	"enemyPerceptionRangeFactor":        {kind: "float"},
	"bossDamageFactor":                  {kind: "float"},
	"bossHealthFactor":                  {kind: "float"},
	"randomSpawnerAmount":               {kind: "enum", enums: []string{"Low", "Normal", "High"}},
	"aggroPoolAmount":                   {kind: "enum", enums: []string{"Low", "Normal", "High"}},
	"pacifyAllEnemies":                  {kind: "bool"},
	"tamingStartleRepercussion":         {kind: "enum", enums: []string{"LoseSomeProgress", "LoseAllProgress"}},
	"miningDamageFactor":                {kind: "float"},
	"resourceDropStackAmountFactor":     {kind: "float"},
	"plantGrowthSpeedFactor":            {kind: "float"},
	"factoryProductionSpeedFactor":      {kind: "float"},
	"perkUpgradeRecyclingFactor":        {kind: "float"},
	"perkCostFactor":                    {kind: "float"},
	"experienceCombatFactor":            {kind: "float"},
	"experienceMiningFactor":            {kind: "float"},
	"experienceExplorationQuestsFactor": {kind: "float"},
}

func applyGameSetting(gs map[string]interface{}, key, raw string) error {
	rule, ok := allowedGameSettings[key]
	if !ok {
		return fmt.Errorf("setting not allowed")
	}
	switch rule.kind {
	case "float":
		if raw == "" {
			return nil
		}
		val, err := strconv.ParseFloat(raw, 64)
		if err != nil {
			return err
		}
		gs[key] = val
	case "bool":
		gs[key] = parseBoolValue(raw)
	case "enum":
		if raw == "" {
			return nil
		}
		okVal := false
		for _, ev := range rule.enums {
			if raw == ev {
				okVal = true
				break
			}
		}
		if !okVal {
			return fmt.Errorf("must be one of %v", rule.enums)
		}
		gs[key] = raw
	default:
		return fmt.Errorf("unsupported kind")
	}
	return nil
}

func (s *BackupService) ensureSaveDir() error {
	return os.MkdirAll(s.cfg.SaveDir, 0o755)
}

func (s *BackupService) updateGroupPasswords(updates map[string]string) error {
	cfgPath := s.serverConfigPath()
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
	return filepath.Clean(s.cfg.ServerConfigPath)
}

func (s *BackupService) serverConfigTxtPath() string {
	return filepath.Clean(s.cfg.ServerConfigTxtPath)
}

func (s *BackupService) readServerConfig() (*serverConfigView, error) {
	cfgPath := s.serverConfigPath()
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		if os.IsNotExist(err) {
			return &serverConfigView{
				Name:               getenv("SERVER_NAME", "Enshrouded Server"),
				SlotCount:          atoiEnv("MAX_PLAYERS", 8),
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
		view.GameSettings = gs
		if v := asInt64(gs["dayTimeDuration"]); v > 0 {
			view.DayTimeMinutes = int(v / int64(time.Minute))
		}
		if v := asInt64(gs["nightTimeDuration"]); v > 0 {
			view.NightTimeMinutes = int(v / int64(time.Minute))
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
	if len(p.GameSettings) > 0 {
		for key, raw := range p.GameSettings {
			if err := applyGameSetting(gs, key, raw); err != nil {
				return fmt.Errorf("invalid %s: %w", key, err)
			}
		}
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
		"slotCount":          atoiEnv("MAX_PLAYERS", 8),
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
		"SERVER_NAME": getenv("SERVER_NAME", "Enshrouded Server"),
		"MAX_PLAYERS": getenv("MAX_PLAYERS", "8"),
		"GAME_PORT":   getenv("GAME_PORT", "15636"),
		"QUERY_PORT":  getenv("QUERY_PORT", "15637"),
		"SAVE_DIR":    getenv("SAVE_DIR", "/data/savegame"),
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

	keys := []string{"SERVER_NAME", "MAX_PLAYERS", "GAME_PORT", "QUERY_PORT", "SAVE_DIR"}
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
	respondJSONStatus(w, http.StatusOK, payload)
}

func respondJSONStatus(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(true)
	_ = enc.Encode(payload)
}

func atoiQuery(r *http.Request, key string, fallback int) int {
	if value, err := strconv.Atoi(r.URL.Query().Get(key)); err == nil {
		return value
	}
	return fallback
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
