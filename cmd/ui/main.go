package main

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/csrf"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"

	"github.com/JimStroomberg/enshrouded-dedi/internal/a2s"
)

//go:embed static/logo.svg
var staticAssets embed.FS

// UIConfig holds env configuration.
type UIConfig struct {
	StackName     string
	ServerName    string
	LogoURL       string
	AdminUser     string
	AdminPass     string
	SessionSecret string
	SessionCrypt  string
	CSRFKey       string
	SecureCookies bool
	BackupAPI     string
	BackupToken   string
	SessionHours  int
	AllowInsecure bool
	A2SEnabled    bool
	A2SAddr       string
	A2STimeout    time.Duration
	A2SCacheTTL   time.Duration
}

type Server struct {
	cfg         UIConfig
	store       *sessions.CookieStore
	client      *http.Client
	logger      *log.Logger
	tmpl        *template.Template
	a2sMu       sync.Mutex
	a2sCached   a2sCache
	a2sEnabled  bool
	a2sAddr     string
	a2sTimeout  time.Duration
	a2sCacheTTL time.Duration
	loginGuard  *loginLimiter
}

type statusResponse struct {
	ID      string      `json:"id"`
	Name    string      `json:"name"`
	State   string      `json:"state"`
	Running bool        `json:"running"`
	Health  interface{} `json:"health"`
}

type steamState struct {
	Mode      string `json:"mode"`
	Username  string `json:"username"`
	HasCreds  bool   `json:"has_creds"`
	GuardHint bool   `json:"guard_hint"`
	Chosen    bool   `json:"chosen"`
	LastError string `json:"last_error,omitempty"`
}

type backupItem struct {
	Key          string    `json:"Key"`
	Size         int64     `json:"Size"`
	LastModified time.Time `json:"LastModified"`
}

type jobView struct {
	ID         string                 `json:"id"`
	Type       string                 `json:"type"`
	State      string                 `json:"state"`
	CreatedAt  time.Time              `json:"created_at"`
	FinishedAt *time.Time             `json:"finished_at,omitempty"`
	DurationMS int64                  `json:"duration_ms,omitempty"`
	Result     map[string]interface{} `json:"result,omitempty"`
	Error      string                 `json:"error,omitempty"`
}

type operationsView struct {
	NextScheduledRun *time.Time `json:"next_scheduled_run,omitempty"`
	LastBackup       *struct {
		Name           string    `json:"name"`
		Size           int64     `json:"size"`
		LastModified   time.Time `json:"last_modified"`
		AgeSeconds     int64     `json:"age_seconds"`
		ChecksumStatus string    `json:"checksum_status"`
	} `json:"last_backup,omitempty"`
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
	GameSettings       map[string]interface{} `json:"game_settings"`
}

type a2sInfo = a2s.Info

type a2sCache struct {
	info *a2sInfo
	err  error
	ts   time.Time
}

type apiStatus struct {
	Status *statusResponse `json:"status,omitempty"`
	Stats  *a2sInfo        `json:"stats,omitempty"`
	Error  string          `json:"error,omitempty"`
}

func main() {
	cfg := UIConfig{
		StackName:     getenv("STACK_NAME", "Enshrouded Stack"),
		ServerName:    getenv("UI_SERVER_NAME", getenv("SERVER_NAME", "Enshrouded Server")),
		LogoURL:       getenv("UI_LOGO_URL", "/static/logo.svg"),
		AdminUser:     getenv("UI_ADMIN_USERNAME", "admin"),
		AdminPass:     getenv("UI_ADMIN_PASSWORD", ""),
		SessionSecret: getenv("UI_SESSION_SECRET", ""),
		SessionCrypt:  getenv("UI_SESSION_ENCRYPTION_KEY", ""),
		CSRFKey:       getenv("UI_CSRF_KEY", ""),
		SecureCookies: envBool("UI_SECURE_COOKIES", false),
		BackupAPI:     getenv("BACKUP_API_URL", "http://backup:7000"),
		BackupToken:   getenv("UI_INTERNAL_TOKEN", ""),
		SessionHours:  atoiEnv("UI_SESSION_HOURS", 24),
		AllowInsecure: envBool("ALLOW_INSECURE_DEFAULTS", false),
		A2SEnabled:    envBool("A2S_ENABLED", true),
		A2SAddr:       getenv("A2S_ADDR", "enshrouded:15637"),
		A2STimeout:    durationMsEnv("A2S_TIMEOUT_MS", 1500),
		A2SCacheTTL:   durationSecEnv("A2S_CACHE_SECONDS", 10),
	}
	if err := validateUIConfig(cfg); err != nil {
		log.Fatalf("invalid UI configuration: %v", err)
	}

	store := sessions.NewCookieStore([]byte(cfg.SessionSecret), []byte(cfg.SessionCrypt))
	store.Options = &sessions.Options{MaxAge: cfg.SessionHours * 3600, HttpOnly: true, Secure: cfg.SecureCookies, SameSite: http.SameSiteLaxMode, Path: "/"}

	tmpl := template.Must(template.New("page").Funcs(template.FuncMap{
		"formatBytes": formatBytes,
		"join":        strings.Join,
	}).Parse(pageTemplate))

	srv := &Server{
		cfg:   cfg,
		store: store,
		client: &http.Client{
			Timeout:   15 * time.Minute,
			Transport: &tokenTransport{base: http.DefaultTransport, token: cfg.BackupToken},
		},
		logger:      log.New(os.Stdout, "ui ", log.LstdFlags|log.Lmsgprefix),
		tmpl:        tmpl,
		a2sEnabled:  cfg.A2SEnabled,
		a2sAddr:     cfg.A2SAddr,
		a2sTimeout:  cfg.A2STimeout,
		a2sCacheTTL: cfg.A2SCacheTTL,
		loginGuard:  newLoginLimiter(5, 15*time.Minute),
	}

	csrfHandler := srv.handler()

	addr := ":8080"
	httpServer := &http.Server{
		Addr:              addr,
		Handler:           csrfHandler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Minute,
		WriteTimeout:      15 * time.Minute,
		IdleTimeout:       60 * time.Second,
	}
	shutdownCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-shutdownCtx.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(ctx); err != nil {
			srv.logger.Printf("http shutdown error: %v", err)
		}
	}()

	srv.logger.Printf("listening on %s secure_cookies=%t", addr, cfg.SecureCookies)
	if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		srv.logger.Fatalf("http server error: %v", err)
	}
}

func (s *Server) handler() http.Handler {
	r := mux.NewRouter()
	r.PathPrefix("/static/").Handler(http.FileServer(http.FS(staticAssets))).Methods(http.MethodGet)
	r.HandleFunc("/health", s.handleHealth).Methods(http.MethodGet)
	r.HandleFunc("/ready", s.handleReady).Methods(http.MethodGet)
	r.HandleFunc("/", s.handleIndex).Methods(http.MethodGet)
	r.HandleFunc("/login", s.handleLogin).Methods(http.MethodPost)
	r.HandleFunc("/logout", s.handleLogout).Methods(http.MethodPost)
	r.HandleFunc("/logs", s.requireAuth(s.handleLogs)).Methods(http.MethodGet)

	r.HandleFunc("/action/restart", s.requireAuth(s.handleActionRestart)).Methods(http.MethodPost)
	r.HandleFunc("/action/update", s.requireAuth(s.handleActionUpdate)).Methods(http.MethodPost)
	r.HandleFunc("/action/backup", s.requireAuth(s.handleActionBackup)).Methods(http.MethodPost)
	r.HandleFunc("/action/restore", s.requireAuth(s.handleActionRestore)).Methods(http.MethodPost)
	r.HandleFunc("/action/upload", s.requireAuth(s.handleActionUpload)).Methods(http.MethodPost)
	r.HandleFunc("/action/steam-auth", s.requireAuth(s.handleActionSteamAuth)).Methods(http.MethodPost)
	r.HandleFunc("/action/steam-anon", s.requireAuth(s.handleActionSteamAnon)).Methods(http.MethodPost)
	r.HandleFunc("/action/groups", s.requireAuth(s.handleActionGroupPasswords)).Methods(http.MethodPost)
	r.HandleFunc("/action/server-config", s.requireAuth(s.handleActionServerConfig)).Methods(http.MethodPost)
	r.HandleFunc("/backup/download", s.requireAuth(s.handleDownloadBackup)).Methods(http.MethodGet)
	r.HandleFunc("/backup/contents", s.requireAuth(s.handleBackupContents)).Methods(http.MethodGet)
	r.HandleFunc("/backup/preview", s.requireAuth(s.handleBackupPreview)).Methods(http.MethodGet)
	r.HandleFunc("/diagnostics", s.requireAuth(s.handleDiagnostics)).Methods(http.MethodGet)

	r.HandleFunc("/api/status", s.handleAPIStatus).Methods(http.MethodGet)

	protected := csrf.Protect(
		[]byte(s.cfg.CSRFKey),
		csrf.Secure(s.cfg.SecureCookies),
		csrf.HttpOnly(true),
		csrf.Path("/"),
		csrf.SameSite(csrf.SameSiteLaxMode),
		csrf.ErrorHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			s.logger.Printf("csrf rejected method=%s path=%s remote=%s", r.Method, r.URL.Path, remoteIP(r))
			http.Error(w, "invalid or expired form; refresh the page and try again", http.StatusForbidden)
		})),
	)(r)
	return securityHeaders(protected)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `{"status":"ok"}`)
}

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	url := fmt.Sprintf("%s/ready", strings.TrimRight(s.cfg.BackupAPI, "/"))
	req, _ := http.NewRequestWithContext(r.Context(), http.MethodGet, url, nil)
	resp, err := s.client.Do(req)
	if err != nil {
		http.Error(w, "backup service unavailable", http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, io.LimitReader(resp.Body, 1<<20))
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	session, _ := s.store.Get(r, "enshrouded-ui")
	loggedIn := session.Values["auth"] == true

	status, _ := s.fetchStatus(r.Context())
	st := &steamState{Mode: "unset"}
	stats, statsErr := s.fetchServerStats(r.Context())
	if statsErr != nil {
		s.logger.Printf("a2s query error: %v", statsErr)
	}
	var backups []backupItem
	var jobs []jobView
	var operations *operationsView
	serverCfg := &serverConfigView{}
	if loggedIn {
		backups, _ = s.fetchBackups(r.Context())
		jobs, _ = s.fetchJobs(r.Context())
		operations, _ = s.fetchOperations(r.Context())
		if fetched, err := s.fetchSteamState(r.Context()); err == nil && fetched != nil {
			st = fetched
		}
		if fetched, err := s.fetchServerConfig(r.Context()); err == nil && fetched != nil {
			serverCfg = fetched
		}
	}

	serverName := s.cfg.ServerName
	if serverCfg.Name != "" {
		serverName = serverCfg.Name
	}

	data := map[string]interface{}{
		"StackName":  s.cfg.StackName,
		"ServerName": serverName,
		"LogoURL":    s.cfg.LogoURL,
		"SteamState": st,
		"Status":     status,
		"Stats":      stats,
		"StatsErr":   statsErr,
		"Backups":    backups,
		"Jobs":       jobs,
		"Operations": operations,
		"LoggedIn":   loggedIn,
		"Message":    r.URL.Query().Get("msg"),
		"ServerCfg":  serverCfg,
		"CSRFField":  csrf.TemplateField(r),
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.Execute(w, data); err != nil {
		s.logger.Printf("template render error: %v", err)
	}
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/?msg=Invalid+form", http.StatusSeeOther)
		return
	}
	user := r.FormValue("username")
	pass := r.FormValue("password")
	ip := remoteIP(r)
	if !s.loginGuard.allow(ip, time.Now()) {
		s.logger.Printf("login throttled remote=%s", ip)
		http.Error(w, "too many login attempts; try again later", http.StatusTooManyRequests)
		return
	}
	if constantTimeEqual(user, s.cfg.AdminUser) && constantTimeEqual(pass, s.cfg.AdminPass) {
		s.loginGuard.success(ip)
		session, _ := s.store.Get(r, "enshrouded-ui")
		session.Values["auth"] = true
		_ = session.Save(r, w)
		http.Redirect(w, r, "/?msg=Logged+in", http.StatusSeeOther)
		return
	}
	s.loginGuard.failure(ip, time.Now())
	s.logger.Printf("login rejected remote=%s", ip)
	http.Redirect(w, r, "/?msg=Invalid+credentials", http.StatusSeeOther)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	session, _ := s.store.Get(r, "enshrouded-ui")
	session.Options.MaxAge = -1
	_ = session.Save(r, w)
	http.Redirect(w, r, "/?msg=Logged+out", http.StatusSeeOther)
}

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	url := fmt.Sprintf("%s/logs", strings.TrimRight(s.cfg.BackupAPI, "/"))
	resp, err := s.client.Get(url)
	if err != nil {
		http.Error(w, "failed to fetch logs", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		http.Error(w, "upstream log error", http.StatusBadGateway)
		return
	}
	for k, v := range resp.Header {
		if len(v) > 0 && (strings.EqualFold(k, "Content-Type") || strings.EqualFold(k, "Content-Disposition")) {
			w.Header().Set(k, v[0])
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func (s *Server) handleDownloadBackup(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if name == "" {
		http.Error(w, "backup name required", http.StatusBadRequest)
		return
	}
	url := fmt.Sprintf("%s/backups/download?name=%s", strings.TrimRight(s.cfg.BackupAPI, "/"), url.QueryEscape(name))
	resp, err := s.client.Get(url)
	if err != nil {
		http.Error(w, "failed to fetch backup", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		http.Error(w, "backup download error", http.StatusBadGateway)
		return
	}
	for k, v := range resp.Header {
		if len(v) > 0 && (strings.EqualFold(k, "Content-Type") || strings.EqualFold(k, "Content-Disposition") || strings.EqualFold(k, "Content-Length")) {
			w.Header().Set(k, v[0])
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func (s *Server) handleBackupContents(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if name == "" {
		http.Error(w, "backup name required", http.StatusBadRequest)
		return
	}
	url := fmt.Sprintf("%s/backups/contents?name=%s", strings.TrimRight(s.cfg.BackupAPI, "/"), url.QueryEscape(name))
	resp, err := s.client.Get(url)
	if err != nil {
		http.Error(w, "failed to fetch contents", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		http.Error(w, "backup contents error", http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func (s *Server) handleBackupPreview(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if name == "" {
		http.Error(w, "backup name required", http.StatusBadRequest)
		return
	}
	upstream := fmt.Sprintf("%s/backups/preview?name=%s", strings.TrimRight(s.cfg.BackupAPI, "/"), url.QueryEscape(name))
	s.proxyJSON(w, r, upstream)
}

func (s *Server) handleDiagnostics(w http.ResponseWriter, r *http.Request) {
	upstream := fmt.Sprintf("%s/diagnostics", strings.TrimRight(s.cfg.BackupAPI, "/"))
	resp, err := s.client.Get(upstream)
	if err != nil {
		http.Error(w, "failed to build diagnostics", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		http.Error(w, "diagnostics unavailable", http.StatusBadGateway)
		return
	}
	for _, header := range []string{"Content-Type", "Content-Disposition", "Content-Length"} {
		if value := resp.Header.Get(header); value != "" {
			w.Header().Set(header, value)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func (s *Server) proxyJSON(w http.ResponseWriter, r *http.Request, upstream string) {
	req, _ := http.NewRequestWithContext(r.Context(), http.MethodGet, upstream, nil)
	resp, err := s.client.Do(req)
	if err != nil {
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, io.LimitReader(resp.Body, 8<<20))
}

func (s *Server) handleActionRestart(w http.ResponseWriter, r *http.Request) {
	if err := s.triggerPOST("/server/restart", nil); err != nil {
		http.Redirect(w, r, "/?msg=Restart+failed", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/?msg=Restarting", http.StatusSeeOther)
}

func (s *Server) handleActionUpdate(w http.ResponseWriter, r *http.Request) {
	if err := s.triggerPOST("/server/update", nil); err != nil {
		http.Redirect(w, r, "/?msg=Update+failed", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/?msg=Update+triggered", http.StatusSeeOther)
}

func (s *Server) handleActionBackup(w http.ResponseWriter, r *http.Request) {
	if err := s.triggerPOST("/backup", nil); err != nil {
		http.Redirect(w, r, "/?msg=Backup+failed", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/?msg=Backup+started", http.StatusSeeOther)
}

func (s *Server) handleActionRestore(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/?msg=Invalid+request", http.StatusSeeOther)
		return
	}
	name := r.FormValue("name")
	if name == "" {
		http.Redirect(w, r, "/?msg=Backup+name+required", http.StatusSeeOther)
		return
	}
	body := map[string]interface{}{
		"name":          name,
		"backup_before": parseFormBool(r.FormValue("backup_before")),
	}
	if err := s.triggerPOST("/restore", body); err != nil {
		http.Redirect(w, r, "/?msg=Restore+failed", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/?msg=Restore+started", http.StatusSeeOther)
}

func (s *Server) handleActionUpload(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 512<<20)
	if err := r.ParseMultipartForm(512 << 20); err != nil {
		http.Redirect(w, r, "/?msg=Upload+error", http.StatusSeeOther)
		return
	}
	backupBefore := parseFormBool(r.FormValue("backup_before"))
	file, header, err := r.FormFile("file")
	if err != nil {
		http.Redirect(w, r, "/?msg=File+required", http.StatusSeeOther)
		return
	}
	defer file.Close()

	url := fmt.Sprintf("%s/upload", strings.TrimRight(s.cfg.BackupAPI, "/"))
	pr, pw := io.Pipe()
	mw := multipart.NewWriter(pw)

	go func() {
		defer pw.Close()
		defer mw.Close()
		if backupBefore {
			_ = mw.WriteField("backup_before", "true")
		}
		part, err := mw.CreateFormFile("file", filepath.Base(header.Filename))
		if err != nil {
			pw.CloseWithError(err)
			return
		}
		if _, err := io.Copy(part, file); err != nil {
			pw.CloseWithError(err)
			return
		}
	}()

	req, _ := http.NewRequest(http.MethodPost, url, pr)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	resp, err := s.client.Do(req)
	if err != nil {
		http.Redirect(w, r, "/?msg=Upload+failed", http.StatusSeeOther)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		http.Redirect(w, r, "/?msg=Upload+failed", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/?msg=Upload+and+restore+queued", http.StatusSeeOther)
}

func (s *Server) handleAPIStatus(w http.ResponseWriter, r *http.Request) {
	status, err := s.fetchStatus(r.Context())
	stats, _ := s.fetchServerStats(r.Context())
	resp := apiStatus{Status: status, Stats: stats}
	if err != nil {
		resp.Error = "failed to fetch status"
		w.WriteHeader(http.StatusBadGateway)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) fetchStatus(ctx context.Context) (*statusResponse, error) {
	url := fmt.Sprintf("%s/status", strings.TrimRight(s.cfg.BackupAPI, "/"))
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("upstream status %s", resp.Status)
	}
	var out statusResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (s *Server) fetchBackups(ctx context.Context) ([]backupItem, error) {
	url := fmt.Sprintf("%s/backups", strings.TrimRight(s.cfg.BackupAPI, "/"))
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("upstream status %s", resp.Status)
	}
	var items []backupItem
	if err := json.NewDecoder(resp.Body).Decode(&items); err != nil {
		return nil, err
	}
	return items, nil
}

func (s *Server) fetchJobs(ctx context.Context) ([]jobView, error) {
	url := fmt.Sprintf("%s/jobs?limit=12", strings.TrimRight(s.cfg.BackupAPI, "/"))
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("upstream status %s", resp.Status)
	}
	var items []jobView
	if err := json.NewDecoder(resp.Body).Decode(&items); err != nil {
		return nil, err
	}
	return items, nil
}

func (s *Server) fetchOperations(ctx context.Context) (*operationsView, error) {
	url := fmt.Sprintf("%s/operations/status", strings.TrimRight(s.cfg.BackupAPI, "/"))
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("upstream status %s", resp.Status)
	}
	var status operationsView
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return nil, err
	}
	return &status, nil
}

func (s *Server) fetchServerConfig(ctx context.Context) (*serverConfigView, error) {
	url := fmt.Sprintf("%s/server/config", strings.TrimRight(s.cfg.BackupAPI, "/"))
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("upstream status %s", resp.Status)
	}
	var cfg serverConfigView
	if err := json.NewDecoder(resp.Body).Decode(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (s *Server) fetchSteamState(ctx context.Context) (*steamState, error) {
	url := fmt.Sprintf("%s/steam/state", strings.TrimRight(s.cfg.BackupAPI, "/"))
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	resp, err := s.client.Do(req)
	if err != nil {
		return &steamState{Mode: "unset"}, nil
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return &steamState{Mode: "unset"}, fmt.Errorf("upstream status %s", resp.Status)
	}
	var st steamState
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		return &steamState{Mode: "unset"}, nil
	}
	return &st, nil
}

func (s *Server) fetchServerStats(ctx context.Context) (*a2sInfo, error) {
	if !s.a2sEnabled {
		return nil, nil
	}
	now := time.Now()
	s.a2sMu.Lock()
	if s.a2sCached.info != nil || s.a2sCached.err != nil {
		if now.Sub(s.a2sCached.ts) < s.a2sCacheTTL {
			info := s.a2sCached.info
			err := s.a2sCached.err
			s.a2sMu.Unlock()
			return info, err
		}
	}
	s.a2sMu.Unlock()

	info, err := a2s.Query(s.a2sAddr, s.a2sTimeout)

	s.a2sMu.Lock()
	s.a2sCached = a2sCache{info: info, err: err, ts: time.Now()}
	s.a2sMu.Unlock()
	return info, err
}

func (s *Server) triggerPOST(path string, payload interface{}) error {
	url := fmt.Sprintf("%s%s", strings.TrimRight(s.cfg.BackupAPI, "/"), path)
	var body io.Reader
	if payload != nil {
		data, _ := json.Marshal(payload)
		body = bytes.NewReader(data)
	}
	req, _ := http.NewRequest(http.MethodPost, url, body)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("upstream error: %s", resp.Status)
	}
	return nil
}

func (s *Server) handleActionSteamAuth(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/?msg=Invalid+request", http.StatusSeeOther)
		return
	}
	user := r.FormValue("steam_username")
	pass := r.FormValue("steam_password")
	code := r.FormValue("steam_guard")
	if user == "" || pass == "" {
		http.Redirect(w, r, "/?msg=Steam+user+and+password+required", http.StatusSeeOther)
		return
	}
	payload := map[string]string{
		"username":   user,
		"password":   pass,
		"guard_code": code,
	}
	if err := s.triggerPOST("/steam/auth", payload); err != nil {
		http.Redirect(w, r, "/?msg=Steam+auth+failed", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/?msg=Steam+credentials+stored;+server+restarting", http.StatusSeeOther)
}

func (s *Server) handleActionSteamAnon(w http.ResponseWriter, r *http.Request) {
	if err := s.triggerPOST("/steam/anonymous", nil); err != nil {
		http.Redirect(w, r, "/?msg=Switch+to+anonymous+failed", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/?msg=Switched+to+anonymous;+server+restarting", http.StatusSeeOther)
}

func (s *Server) handleActionGroupPasswords(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/?msg=Invalid+request", http.StatusSeeOther)
		return
	}
	payload := map[string]string{}
	addField := func(key, val string) {
		v := strings.TrimSpace(val)
		if v == "" {
			return
		}
		payload[key] = v
	}
	addField("admin", r.FormValue("group_admin"))
	addField("friend", r.FormValue("group_friend"))
	addField("guest", r.FormValue("group_guest"))
	addField("visitor", r.FormValue("group_visitor"))
	if len(payload) == 0 {
		http.Redirect(w, r, "/?msg=No+group+passwords+provided", http.StatusSeeOther)
		return
	}
	if err := s.triggerPOST("/server/groups", payload); err != nil {
		http.Redirect(w, r, "/?msg=Group+update+failed", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/?msg=Group+passwords+updated;+server+restarting", http.StatusSeeOther)
}

func (s *Server) handleActionServerConfig(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/?msg=Invalid+request", http.StatusSeeOther)
		return
	}
	payload := map[string]interface{}{}
	if v := strings.TrimSpace(r.FormValue("server_name")); v != "" {
		payload["name"] = v
	}
	if parseFormBool(r.FormValue("clear_server_password")) {
		payload["server_password"] = ""
	} else if v := strings.TrimSpace(r.FormValue("server_password")); v != "" {
		payload["server_password"] = v
	}
	if v := strings.TrimSpace(r.FormValue("slot_count")); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			payload["slot_count"] = i
		}
	}
	if v := strings.TrimSpace(r.FormValue("voice_chat_mode")); v != "" {
		payload["voice_chat_mode"] = v
	}
	if v, ok := getFormBool(r, "enable_voice_chat"); ok {
		payload["enable_voice_chat"] = v
	}
	if v, ok := getFormBool(r, "enable_text_chat"); ok {
		payload["enable_text_chat"] = v
	}
	if v := strings.TrimSpace(r.FormValue("game_settings_preset")); v != "" {
		payload["game_settings_preset"] = v
	}
	if v := strings.TrimSpace(r.FormValue("day_time_minutes")); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			payload["day_time_minutes"] = i
		}
	}
	if v := strings.TrimSpace(r.FormValue("night_time_minutes")); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			payload["night_time_minutes"] = i
		}
	}
	tags := parseTags(r.FormValue("tags"))
	if tags != nil {
		payload["tags"] = tags
	}
	gs := collectGameSettings(r)
	if len(gs) > 0 {
		payload["game_settings"] = gs
	}
	if len(payload) == 0 {
		http.Redirect(w, r, "/?msg=No+changes+submitted", http.StatusSeeOther)
		return
	}
	if err := s.triggerPOST("/server/config", payload); err != nil {
		http.Redirect(w, r, "/?msg=Server+config+update+failed", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/?msg=Server+config+updated;+restarting", http.StatusSeeOther)
}

func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, _ := s.store.Get(r, "enshrouded-ui")
		if session.Values["auth"] != true {
			http.Redirect(w, r, "/?msg=Login+required", http.StatusSeeOther)
			return
		}
		next(w, r)
	}
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data: https:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'self'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
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

func parseFormBool(val string) bool {
	switch strings.ToLower(strings.TrimSpace(val)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func getFormBool(r *http.Request, name string) (bool, bool) {
	vals, ok := r.Form[name]
	if !ok || len(vals) == 0 {
		return false, false
	}
	return parseFormBool(vals[len(vals)-1]), true
}

func collectGameSettings(r *http.Request) map[string]string {
	keys := []string{
		"playerHealthFactor",
		"playerStaminaFactor",
		"enableDurability",
		"enableStarvingDebuff",
		"foodBuffDurationFactor",
		"shroudTimeFactor",
		"tombstoneMode",
		"weatherFrequency",
		"enemyDamageFactor",
		"enemyHealthFactor",
		"enemyPerceptionRangeFactor",
		"bossDamageFactor",
		"bossHealthFactor",
		"randomSpawnerAmount",
		"aggroPoolAmount",
		"pacifyAllEnemies",
		"tamingStartleRepercussion",
		"miningDamageFactor",
		"resourceDropStackAmountFactor",
		"plantGrowthSpeedFactor",
		"factoryProductionSpeedFactor",
		"perkUpgradeRecyclingFactor",
		"perkCostFactor",
		"experienceCombatFactor",
		"experienceMiningFactor",
		"experienceExplorationQuestsFactor",
	}
	out := map[string]string{}
	for _, k := range keys {
		vals := r.Form["gs_"+k]
		if len(vals) == 0 {
			continue
		}
		val := strings.TrimSpace(vals[len(vals)-1])
		if val == "" {
			continue
		}
		out[k] = val
	}
	return out
}

func parseTags(val string) []string {
	if strings.TrimSpace(val) == "" {
		return []string{}
	}
	parts := strings.Split(val, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		t := strings.TrimSpace(p)
		if t != "" {
			out = append(out, t)
		}
	}
	return out
}

func envBool(key string, def bool) bool {
	if v := strings.ToLower(os.Getenv(key)); v != "" {
		if v == "1" || v == "true" || v == "yes" || v == "on" {
			return true
		}
		if v == "0" || v == "false" || v == "no" || v == "off" {
			return false
		}
	}
	return def
}

func durationMsEnv(key string, def int) time.Duration {
	if v := os.Getenv(key); v != "" {
		if i, err := strconv.Atoi(v); err == nil && i > 0 {
			return time.Duration(i) * time.Millisecond
		}
	}
	return time.Duration(def) * time.Millisecond
}

func durationSecEnv(key string, def int) time.Duration {
	if v := os.Getenv(key); v != "" {
		if i, err := strconv.Atoi(v); err == nil && i > 0 {
			return time.Duration(i) * time.Second
		}
	}
	return time.Duration(def) * time.Second
}

//go:embed templates/page.html
var pageTemplate string

func formatBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for n/div >= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

// Template function map could be extended later.
