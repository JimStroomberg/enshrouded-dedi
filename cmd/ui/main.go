package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
)

// UIConfig holds env configuration.
type UIConfig struct {
	StackName     string
	ServerName    string
	LogoURL       string
	AdminUser     string
	AdminPass     string
	SessionSecret string
	BackupAPI     string
	SessionHours  int
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
	ServerPassword     string                 `json:"server_password"`
	GameSettings       map[string]interface{} `json:"game_settings"`
}

type a2sInfo struct {
	Name       string `json:"name"`
	Map        string `json:"map"`
	Players    int    `json:"players"`
	MaxPlayers int    `json:"max_players"`
	Bots       int    `json:"bots"`
	Version    string `json:"version"`
	VAC        bool   `json:"vac"`
}

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
		LogoURL:       getenv("UI_LOGO_URL", "https://seafile.keengames.com/thumbnail/01124f597b214107abf6/1024/Logos/Enshrouded_graphical_logo_TRANSPARENT.png"),
		AdminUser:     getenv("UI_ADMIN_USERNAME", "admin"),
		AdminPass:     getenv("UI_ADMIN_PASSWORD", "changeme"),
		SessionSecret: getenv("UI_SESSION_SECRET", "change-me"),
		BackupAPI:     getenv("BACKUP_API_URL", "http://backup:7000"),
		SessionHours:  atoiEnv("UI_SESSION_HOURS", 24),
		A2SEnabled:    envBool("A2S_ENABLED", true),
		A2SAddr:       getenv("A2S_ADDR", "enshrouded:15637"),
		A2STimeout:    durationMsEnv("A2S_TIMEOUT_MS", 1500),
		A2SCacheTTL:   durationSecEnv("A2S_CACHE_SECONDS", 10),
	}

	store := sessions.NewCookieStore([]byte(cfg.SessionSecret))
	store.Options = &sessions.Options{MaxAge: cfg.SessionHours * 3600, HttpOnly: true, SameSite: http.SameSiteLaxMode, Path: "/"}

	tmpl := template.Must(template.New("page").Funcs(template.FuncMap{
		"formatBytes": formatBytes,
		"join":        strings.Join,
	}).Parse(pageTemplate))

	srv := &Server{
		cfg:         cfg,
		store:       store,
		client:      &http.Client{Timeout: 10 * time.Second},
		logger:      log.New(os.Stdout, "ui ", log.LstdFlags|log.Lmsgprefix),
		tmpl:        tmpl,
		a2sEnabled:  cfg.A2SEnabled,
		a2sAddr:     cfg.A2SAddr,
		a2sTimeout:  cfg.A2STimeout,
		a2sCacheTTL: cfg.A2SCacheTTL,
	}

	r := mux.NewRouter()
	r.HandleFunc("/health", srv.handleHealth).Methods(http.MethodGet)
	r.HandleFunc("/", srv.handleIndex).Methods(http.MethodGet)
	r.HandleFunc("/login", srv.handleLogin).Methods(http.MethodPost)
	r.HandleFunc("/logout", srv.handleLogout).Methods(http.MethodPost)
	r.HandleFunc("/logs", srv.requireAuth(srv.handleLogs)).Methods(http.MethodGet)

	r.HandleFunc("/action/restart", srv.requireAuth(srv.handleActionRestart)).Methods(http.MethodPost)
	r.HandleFunc("/action/update", srv.requireAuth(srv.handleActionUpdate)).Methods(http.MethodPost)
	r.HandleFunc("/action/backup", srv.requireAuth(srv.handleActionBackup)).Methods(http.MethodPost)
	r.HandleFunc("/action/restore", srv.requireAuth(srv.handleActionRestore)).Methods(http.MethodPost)
	r.HandleFunc("/action/upload", srv.requireAuth(srv.handleActionUpload)).Methods(http.MethodPost)
	r.HandleFunc("/action/steam-auth", srv.requireAuth(srv.handleActionSteamAuth)).Methods(http.MethodPost)
	r.HandleFunc("/action/steam-anon", srv.requireAuth(srv.handleActionSteamAnon)).Methods(http.MethodPost)
	r.HandleFunc("/action/groups", srv.requireAuth(srv.handleActionGroupPasswords)).Methods(http.MethodPost)
	r.HandleFunc("/action/server-config", srv.requireAuth(srv.handleActionServerConfig)).Methods(http.MethodPost)
	r.HandleFunc("/backup/download", srv.requireAuth(srv.handleDownloadBackup)).Methods(http.MethodGet)
	r.HandleFunc("/backup/contents", srv.requireAuth(srv.handleBackupContents)).Methods(http.MethodGet)

	r.HandleFunc("/api/status", srv.handleAPIStatus).Methods(http.MethodGet)

	addr := ":8080"
	srv.logger.Printf("listening on %s", addr)
	if err := http.ListenAndServe(addr, r); err != nil {
		srv.logger.Fatalf("http server error: %v", err)
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `{"status":"ok"}`)
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	session, _ := s.store.Get(r, "enshrouded-ui")
	loggedIn := session.Values["auth"] == true

	status, _ := s.fetchStatus(r.Context())
	st := &steamState{Mode: "unset"}
	if fetched, err := s.fetchSteamState(r.Context()); err == nil && fetched != nil {
		st = fetched
	}
	stats, statsErr := s.fetchServerStats(r.Context())
	if statsErr != nil {
		s.logger.Printf("a2s query error: %v", statsErr)
	}
	var backups []backupItem
	if loggedIn {
		backups, _ = s.fetchBackups(r.Context())
	}
	serverCfg, _ := s.fetchServerConfig(r.Context())
	if serverCfg == nil {
		serverCfg = &serverConfigView{}
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
		"LoggedIn":   loggedIn,
		"Message":    r.URL.Query().Get("msg"),
		"ServerCfg":  serverCfg,
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
	if user == s.cfg.AdminUser && pass == s.cfg.AdminPass {
		session, _ := s.store.Get(r, "enshrouded-ui")
		session.Values["auth"] = true
		_ = session.Save(r, w)
		http.Redirect(w, r, "/?msg=Logged+in", http.StatusSeeOther)
		return
	}
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
	http.Redirect(w, r, "/?msg=Upload+restored", http.StatusSeeOther)
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
	var items []backupItem
	if err := json.NewDecoder(resp.Body).Decode(&items); err != nil {
		return nil, err
	}
	return items, nil
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

	info, err := queryA2S(s.a2sAddr, s.a2sTimeout)

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
	// Allow clearing password by sending empty string.
	if v, ok := r.Form["server_password"]; ok {
		if len(v) > 0 {
			payload["server_password"] = strings.TrimSpace(v[len(v)-1])
		} else {
			payload["server_password"] = ""
		}
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

func queryA2S(addr string, timeout time.Duration) (*a2sInfo, error) {
	if timeout <= 0 {
		timeout = 1500 * time.Millisecond
	}
	conn, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	payload := append([]byte{0xFF, 0xFF, 0xFF, 0xFF}, []byte("TSource Engine Query\x00")...)
	buf := make([]byte, 1400)

	readResp := func(msg []byte) ([]byte, error) {
		if _, err := conn.Write(msg); err != nil {
			return nil, err
		}
		n, err := conn.Read(buf)
		if err != nil {
			return nil, err
		}
		if n < 5 {
			return nil, fmt.Errorf("short A2S response")
		}
		return buf[:n], nil
	}

	resp, err := readResp(payload)
	if err != nil {
		return nil, err
	}
	if resp[4] == 'A' {
		if len(resp) < 9 {
			return nil, fmt.Errorf("short A2S challenge")
		}
		challenge := append([]byte{}, resp[5:9]...)
		payloadChallenge := append(append([]byte{}, payload...), challenge...)
		resp, err = readResp(payloadChallenge)
		if err != nil {
			return nil, err
		}
	}
	if resp[4] != 'I' {
		return nil, fmt.Errorf("invalid A2S response")
	}
	data := resp[5:]
	off := 0
	if len(data) < 1 {
		return nil, fmt.Errorf("short A2S response")
	}
	off++ // protocol byte

	name, err := readCString(data, &off)
	if err != nil {
		return nil, err
	}
	mapName, err := readCString(data, &off)
	if err != nil {
		return nil, err
	}
	// skip folder and game strings
	if _, err := readCString(data, &off); err != nil {
		return nil, err
	}
	if _, err := readCString(data, &off); err != nil {
		return nil, err
	}
	if off+7 > len(data) {
		return nil, fmt.Errorf("short A2S response")
	}
	// appID (2 bytes)
	off += 2
	players := int(data[off])
	off++
	maxPlayers := int(data[off])
	off++
	bots := int(data[off])
	off++
	// server type, environment, visibility
	off += 3
	if off >= len(data) {
		return nil, fmt.Errorf("short A2S response")
	}
	vac := data[off] == 1
	off++

	version := ""
	if off < len(data) {
		if v, err := readCString(data, &off); err == nil {
			version = v
		}
	}

	return &a2sInfo{
		Name:       name,
		Map:        mapName,
		Players:    players,
		MaxPlayers: maxPlayers,
		Bots:       bots,
		Version:    version,
		VAC:        vac,
	}, nil
}

func readCString(data []byte, off *int) (string, error) {
	if *off >= len(data) {
		return "", fmt.Errorf("short A2S string")
	}
	idx := bytes.IndexByte(data[*off:], 0)
	if idx == -1 {
		return "", fmt.Errorf("unterminated A2S string")
	}
	start := *off
	*off += idx + 1
	return string(data[start : start+idx]), nil
}

const pageTemplate = `<!doctype html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{{ .StackName }} | Enshrouded</title>
  <style>
    :root {
      --bg: radial-gradient(circle at 15% 20%, #0b1c28, #071018 45%, #04070c 100%);
      --card: rgba(255,255,255,0.05);
      --accent: #f97316;
      --text: #f8fafc;
      --muted: #cbd5e1;
      --border: rgba(255,255,255,0.08);
      --glow: 0 10px 40px rgba(249,115,22,0.25);
      --shadow: 0 30px 80px rgba(0,0,0,0.5);
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      background: var(--bg);
      color: var(--text);
      font-family: "Space Grotesk", "Inter", "Segoe UI", system-ui, -apple-system, sans-serif;
      padding: 24px;
    }
    .shell {
      width: 100%;
      max-width: 960px;
      margin: 0 auto;
      background: linear-gradient(160deg, rgba(255,255,255,0.06), rgba(255,255,255,0.02));
      border: 1px solid var(--border);
      border-radius: 18px;
      padding: 28px;
      box-shadow: var(--shadow);
      backdrop-filter: blur(6px);
    }
    header, .hero {
      display: flex;
      justify-content: space-between;
      gap: 12px;
      flex-wrap: wrap;
      align-items: center;
    }
    h1 { margin: 6px 0 4px 0; font-size: 26px; letter-spacing: 0.01em; }
    .hero { margin-bottom: 18px; }
    .hero-sub { margin: 0; color: var(--muted); }
    .badge { padding: 6px 10px; border-radius: 10px; background: rgba(249,115,22,0.08); border: 1px solid rgba(249,115,22,0.35); font-size: 12px; color: #fb923c; box-shadow: var(--glow); }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 14px; }
    .card { background: var(--card); border: 1px solid var(--border); border-radius: 14px; padding: 16px; }
    .title { font-size: 14px; text-transform: uppercase; letter-spacing: 0.08em; color: var(--muted); margin-bottom: 10px; }
    .status { display: flex; align-items: center; gap: 8px; font-size: 16px; }
    .dot { width: 10px; height: 10px; border-radius: 999px; }
    .dot.ok { background: #34d399; box-shadow: 0 0 0 6px rgba(52,211,153,0.15); }
    .dot.down { background: #f97316; box-shadow: 0 0 0 6px rgba(249,115,22,0.15); }
    form { margin: 0; }
    button, .ghost { appearance: none; border: 1px solid var(--border); background: rgba(255,255,255,0.06); color: var(--text); padding: 10px 12px; border-radius: 10px; cursor: pointer; font-weight: 600; letter-spacing: 0.01em; transition: 0.2s ease; }
    button:hover, .ghost:hover { border-color: var(--accent); box-shadow: var(--glow); }
    .stack { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; }
    .msg { margin-top: 12px; color: var(--accent); font-weight: 600; }
    table { width: 100%; border-collapse: collapse; font-size: 14px; }
    th, td { padding: 8px 6px; text-align: left; color: var(--muted); }
    th { text-transform: uppercase; letter-spacing: 0.05em; font-size: 12px; }
    tr:nth-child(odd) td { background: rgba(255,255,255,0.02); }
    input[type="text"], input[type="password"], input[type="file"] { width: 100%; padding: 10px 12px; border-radius: 10px; border: 1px solid var(--border); background: rgba(255,255,255,0.04); color: var(--text); margin-bottom: 10px; }
    .pill { font-size: 12px; padding: 4px 10px; border-radius: 999px; border: 1px solid var(--border); color: var(--muted); }
    .hero-wrap { display: flex; justify-content: space-between; align-items: center; gap: 12px; flex-wrap: wrap; }
    .logo { max-height: 54px; object-fit: contain; filter: drop-shadow(0 8px 18px rgba(0,0,0,0.35)); }
    .mode-toggle { display: inline-flex; align-items: center; gap: 8px; padding: 8px; border-radius: 12px; border: 1px solid var(--border); background: rgba(255,255,255,0.04); }
    .mode-toggle input { margin: 0; }
    .mode-toggle span { flex: 1; min-width: 0; }
    .mode-toggle input[type="number"], .mode-toggle input[type="text"], .mode-toggle select { max-width: 140px; min-width: 110px; }
    .status-pill { display:inline-flex; align-items:center; gap:8px; padding:6px 10px; border-radius:10px; border:1px solid var(--border); background: rgba(255,255,255,0.04); }
    .status-pill.warn { border-color:#f97316; color:#f97316; }
    .howto { margin: 0; padding-left: 18px; color: var(--muted); }
    .howto li { margin-bottom: 6px; }
  </style>
</head>
<body>
  <div class="shell">
    <div class="hero-wrap">
      <div class="hero">
        <div class="badge">{{ .StackName }}</div>
        <h1>{{ .ServerName }}</h1>
        <p class="hero-sub">Enshrouded dedicated server control</p>
      </div>
      <header>
        <div class="stack">
          {{ if .LoggedIn }}
            <form action="/logout" method="post"><button type="submit">Logout</button></form>
          {{ else }}
            <form action="/login" method="post" class="stack">
              <input type="text" name="username" placeholder="Admin user" required />
              <input type="password" name="password" placeholder="Password" required />
              <button type="submit">Login</button>
            </form>
          {{ end }}
        </div>
        {{ if .LogoURL }}
          <img class="logo" src="{{ .LogoURL }}" alt="Enshrouded" />
        {{ end }}
      </header>
    </div>

    {{ if .Message }}<div class="msg">{{ .Message }}</div>{{ end }}

    <div class="grid" style="margin-bottom:16px;">
      <div class="card">
        <div class="title">Server</div>
        {{ if .Status }}
          <div class="status">
            {{ if .Status.Running }}<div class="dot ok"></div>{{ else }}<div class="dot down"></div>{{ end }}
            <div>
              <div>{{ .Status.Name }}</div>
              <div class="pill" style="margin-top:6px;">State: {{ .Status.State }}</div>
              {{ if .Stats }}
                <div class="pill" style="margin-top:6px;">Players: {{ .Stats.Players }} / {{ .Stats.MaxPlayers }}</div>
                {{ if .Stats.Version }}<div class="pill" style="margin-top:6px;">Build: {{ .Stats.Version }}</div>{{ end }}
                {{ if .Stats.Map }}<div class="pill" style="margin-top:6px;">Map: {{ .Stats.Map }}</div>{{ end }}
              {{ else if .StatsErr }}
                <div class="pill status-pill warn" style="margin-top:6px;">Query failed; retry later.</div>
              {{ end }}
            </div>
          </div>
        {{ else }}
          <div class="status"><div class="dot down"></div><div>Unknown (backup API unreachable)</div></div>
        {{ end }}
      </div>
      {{ if .LoggedIn }}
        <div class="card">
          <div class="title">Actions</div>
          <div class="stack">
            <form action="/action/restart" method="post"><button type="submit">Restart</button></form>
            <form action="/action/update" method="post"><button type="submit">Trigger Update</button></form>
            <form action="/action/backup" method="post"><button type="submit">Backup Now</button></form>
            <a class="ghost" href="/logs">Download Logs</a>
          </div>
        </div>
      {{ end }}
    </div>

    {{ if .LoggedIn }}
    <div class="card" style="margin-bottom:14px;">
      <div class="title">Server Settings</div>
      <form action="/action/server-config" method="post">
        <input type="text" name="server_name" placeholder="Server name" value="{{ .ServerCfg.Name }}" />
        <input type="password" name="server_password" placeholder="Server password (Friend group)" value="{{ .ServerCfg.ServerPassword }}" />
        <label class="mode-toggle" style="width:100%; justify-content:space-between;">
          <span>Max players</span>
          <input type="number" name="slot_count" min="1" max="32" value="{{ if .ServerCfg.SlotCount }}{{ .ServerCfg.SlotCount }}{{ else }}16{{ end }}" style="max-width:100px;" />
        </label>
        <label class="mode-toggle" style="width:100%; justify-content:space-between;">
          <span>Voice chat mode</span>
          <select name="voice_chat_mode" style="padding:8px 10px; border-radius:10px; border:1px solid var(--border); background:rgba(255,255,255,0.04); color:var(--text);">
            <option value="">(no change)</option>
            <option value="Proximity" {{ if eq .ServerCfg.VoiceChatMode "Proximity" }}selected{{ end }}>Proximity</option>
            <option value="Global" {{ if eq .ServerCfg.VoiceChatMode "Global" }}selected{{ end }}>Global</option>
          </select>
        </label>
        <input type="hidden" name="enable_voice_chat" value="false" />
        <label class="mode-toggle">
          <input type="checkbox" name="enable_voice_chat" value="true" {{ if .ServerCfg.EnableVoiceChat }}checked{{ end }} />
          <span>Enable voice chat</span>
        </label>
        <input type="hidden" name="enable_text_chat" value="false" />
        <label class="mode-toggle">
          <input type="checkbox" name="enable_text_chat" value="true" {{ if .ServerCfg.EnableTextChat }}checked{{ end }} />
          <span>Enable text chat</span>
        </label>
        <input type="text" name="game_settings_preset" placeholder="Game settings preset" value="{{ .ServerCfg.GameSettingsPreset }}" />
        <div class="stack">
          <input type="number" name="day_time_minutes" min="1" placeholder="Day duration (minutes)" value="{{ if .ServerCfg.DayTimeMinutes }}{{ .ServerCfg.DayTimeMinutes }}{{ end }}" />
          <input type="number" name="night_time_minutes" min="1" placeholder="Night duration (minutes)" value="{{ if .ServerCfg.NightTimeMinutes }}{{ .ServerCfg.NightTimeMinutes }}{{ end }}" />
        </div>
        <input type="text" name="tags" placeholder="Tags (comma separated)" value="{{ if .ServerCfg.Tags }}{{ join .ServerCfg.Tags ", " }}{{ end }}" />
        <div class="grid" style="margin-top:8px;">
          <div class="card">
            <div class="title">Players</div>
            <label class="mode-toggle" style="justify-content:space-between;">
              <span>Health factor (playerHealthFactor)</span>
              <input type="number" step="0.1" name="gs_playerHealthFactor" placeholder="1.0" value="{{ index .ServerCfg.GameSettings "playerHealthFactor" }}" style="max-width:110px;" />
            </label>
            <label class="mode-toggle" style="justify-content:space-between;">
              <span>Stamina factor (playerStaminaFactor)</span>
              <input type="number" step="0.1" name="gs_playerStaminaFactor" placeholder="1.0" value="{{ index .ServerCfg.GameSettings "playerStaminaFactor" }}" style="max-width:110px;" />
            </label>
            <label class="mode-toggle">
              <input type="checkbox" name="gs_enableDurability" value="true" {{ if eq (index .ServerCfg.GameSettings "enableDurability") true }}checked{{ end }} />
              <span>Durability enabled</span>
            </label>
            <label class="mode-toggle">
              <input type="checkbox" name="gs_enableStarvingDebuff" value="true" {{ if eq (index .ServerCfg.GameSettings "enableStarvingDebuff") true }}checked{{ end }} />
              <span>Starving debuff</span>
            </label>
            <label class="mode-toggle" style="justify-content:space-between;">
              <span>Food buff duration (foodBuffDurationFactor)</span>
              <input type="number" step="0.1" name="gs_foodBuffDurationFactor" placeholder="1.0" value="{{ index .ServerCfg.GameSettings "foodBuffDurationFactor" }}" style="max-width:110px;" />
            </label>
          </div>
          <div class="card">
            <div class="title">Survival</div>
            <label class="mode-toggle" style="justify-content:space-between;">
              <span>Shroud time (shroudTimeFactor)</span>
              <input type="number" step="0.1" name="gs_shroudTimeFactor" placeholder="1.0" value="{{ index .ServerCfg.GameSettings "shroudTimeFactor" }}" style="max-width:110px;" />
            </label>
            <select name="gs_tombstoneMode" style="padding:8px 10px; border-radius:10px; border:1px solid var(--border); background:rgba(255,255,255,0.04); color:var(--text);">
              <option value="">Tombstone mode (no change)</option>
              <option value="AddBackpackMaterials" {{ if eq (index .ServerCfg.GameSettings "tombstoneMode") "AddBackpackMaterials" }}selected{{ end }}>Keep backpack materials</option>
              <option value="DropBackpackMaterials" {{ if eq (index .ServerCfg.GameSettings "tombstoneMode") "DropBackpackMaterials" }}selected{{ end }}>Drop backpack materials</option>
            </select>
            <select name="gs_weatherFrequency" style="padding:8px 10px; border-radius:10px; border:1px solid var(--border); background:rgba(255,255,255,0.04); color:var(--text);">
              <option value="">Weather frequency (no change)</option>
              <option value="Low" {{ if eq (index .ServerCfg.GameSettings "weatherFrequency") "Low" }}selected{{ end }}>Low</option>
              <option value="Normal" {{ if eq (index .ServerCfg.GameSettings "weatherFrequency") "Normal" }}selected{{ end }}>Normal</option>
              <option value="High" {{ if eq (index .ServerCfg.GameSettings "weatherFrequency") "High" }}selected{{ end }}>High</option>
            </select>
          </div>
          <div class="card">
            <div class="title">Enemies</div>
            <label class="mode-toggle" style="justify-content:space-between;">
              <span>Enemy damage (enemyDamageFactor)</span>
              <input type="number" step="0.1" name="gs_enemyDamageFactor" placeholder="1.0" value="{{ index .ServerCfg.GameSettings "enemyDamageFactor" }}" style="max-width:110px;" />
            </label>
            <label class="mode-toggle" style="justify-content:space-between;">
              <span>Enemy health (enemyHealthFactor)</span>
              <input type="number" step="0.1" name="gs_enemyHealthFactor" placeholder="1.0" value="{{ index .ServerCfg.GameSettings "enemyHealthFactor" }}" style="max-width:110px;" />
            </label>
            <label class="mode-toggle" style="justify-content:space-between;">
              <span>Enemy perception (enemyPerceptionRangeFactor)</span>
              <input type="number" step="0.1" name="gs_enemyPerceptionRangeFactor" placeholder="1.0" value="{{ index .ServerCfg.GameSettings "enemyPerceptionRangeFactor" }}" style="max-width:110px;" />
            </label>
            <select name="gs_randomSpawnerAmount" style="padding:8px 10px; border-radius:10px; border:1px solid var(--border); background:rgba(255,255,255,0.04); color:var(--text);">
              <option value="">Spawner amount (no change)</option>
              <option value="Low" {{ if eq (index .ServerCfg.GameSettings "randomSpawnerAmount") "Low" }}selected{{ end }}>Low</option>
              <option value="Normal" {{ if eq (index .ServerCfg.GameSettings "randomSpawnerAmount") "Normal" }}selected{{ end }}>Normal</option>
              <option value="High" {{ if eq (index .ServerCfg.GameSettings "randomSpawnerAmount") "High" }}selected{{ end }}>High</option>
            </select>
            <select name="gs_aggroPoolAmount" style="padding:8px 10px; border-radius:10px; border:1px solid var(--border); background:rgba(255,255,255,0.04); color:var(--text);">
              <option value="">Aggro pool (no change)</option>
              <option value="Low" {{ if eq (index .ServerCfg.GameSettings "aggroPoolAmount") "Low" }}selected{{ end }}>Low</option>
              <option value="Normal" {{ if eq (index .ServerCfg.GameSettings "aggroPoolAmount") "Normal" }}selected{{ end }}>Normal</option>
              <option value="High" {{ if eq (index .ServerCfg.GameSettings "aggroPoolAmount") "High" }}selected{{ end }}>High</option>
            </select>
            <label class="mode-toggle">
              <input type="checkbox" name="gs_pacifyAllEnemies" value="true" {{ if eq (index .ServerCfg.GameSettings "pacifyAllEnemies") true }}checked{{ end }} />
              <span>Pacify all enemies</span>
            </label>
            <select name="gs_tamingStartleRepercussion" style="padding:8px 10px; border-radius:10px; border:1px solid var(--border); background:rgba(255,255,255,0.04); color:var(--text);">
              <option value="">Taming repercussion (no change)</option>
              <option value="LoseSomeProgress" {{ if eq (index .ServerCfg.GameSettings "tamingStartleRepercussion") "LoseSomeProgress" }}selected{{ end }}>Lose some progress</option>
              <option value="LoseAllProgress" {{ if eq (index .ServerCfg.GameSettings "tamingStartleRepercussion") "LoseAllProgress" }}selected{{ end }}>Lose all progress</option>
            </select>
          </div>
          <div class="card">
            <div class="title">Resources / Progression</div>
            <label class="mode-toggle" style="justify-content:space-between;">
              <span>Mining damage (miningDamageFactor)</span>
              <input type="number" step="0.1" name="gs_miningDamageFactor" placeholder="1.0" value="{{ index .ServerCfg.GameSettings "miningDamageFactor" }}" style="max-width:110px;" />
            </label>
            <label class="mode-toggle" style="justify-content:space-between;">
              <span>Resource drop (resourceDropStackAmountFactor)</span>
              <input type="number" step="0.1" name="gs_resourceDropStackAmountFactor" placeholder="1.0" value="{{ index .ServerCfg.GameSettings "resourceDropStackAmountFactor" }}" style="max-width:110px;" />
            </label>
            <label class="mode-toggle" style="justify-content:space-between;">
              <span>Plant growth (plantGrowthSpeedFactor)</span>
              <input type="number" step="0.1" name="gs_plantGrowthSpeedFactor" placeholder="1.0" value="{{ index .ServerCfg.GameSettings "plantGrowthSpeedFactor" }}" style="max-width:110px;" />
            </label>
            <label class="mode-toggle" style="justify-content:space-between;">
              <span>Factory production (factoryProductionSpeedFactor)</span>
              <input type="number" step="0.1" name="gs_factoryProductionSpeedFactor" placeholder="1.0" value="{{ index .ServerCfg.GameSettings "factoryProductionSpeedFactor" }}" style="max-width:110px;" />
            </label>
            <label class="mode-toggle" style="justify-content:space-between;">
              <span>Perk recycling (perkUpgradeRecyclingFactor)</span>
              <input type="number" step="0.1" name="gs_perkUpgradeRecyclingFactor" placeholder="0.5" value="{{ index .ServerCfg.GameSettings "perkUpgradeRecyclingFactor" }}" style="max-width:110px;" />
            </label>
            <label class="mode-toggle" style="justify-content:space-between;">
              <span>Perk cost (perkCostFactor)</span>
              <input type="number" step="0.1" name="gs_perkCostFactor" placeholder="1.0" value="{{ index .ServerCfg.GameSettings "perkCostFactor" }}" style="max-width:110px;" />
            </label>
            <label class="mode-toggle" style="justify-content:space-between;">
              <span>Combat XP (experienceCombatFactor)</span>
              <input type="number" step="0.1" name="gs_experienceCombatFactor" placeholder="1.0" value="{{ index .ServerCfg.GameSettings "experienceCombatFactor" }}" style="max-width:110px;" />
            </label>
            <label class="mode-toggle" style="justify-content:space-between;">
              <span>Mining XP (experienceMiningFactor)</span>
              <input type="number" step="0.1" name="gs_experienceMiningFactor" placeholder="1.0" value="{{ index .ServerCfg.GameSettings "experienceMiningFactor" }}" style="max-width:110px;" />
            </label>
            <label class="mode-toggle" style="justify-content:space-between;">
              <span>Exploration XP (experienceExplorationQuestsFactor)</span>
              <input type="number" step="0.1" name="gs_experienceExplorationQuestsFactor" placeholder="1.0" value="{{ index .ServerCfg.GameSettings "experienceExplorationQuestsFactor" }}" style="max-width:110px;" />
            </label>
          </div>
        </div>
        <button type="submit">Save + Restart</button>
      </form>
      <div class="pill" style="margin-top:6px;">
        Changes apply on restart. Name/password are stored in the server config (not env) so they stay in sync with the running server.
      </div>
    </div>

    <div class="card" style="margin-bottom:14px;">
      <div class="title">Restore</div>
      <form action="/action/restore" method="post" class="stack">
        <select id="restore-select" name="name" style="padding:10px 12px; border-radius:10px; border:1px solid var(--border); background:rgba(255,255,255,0.04); color:var(--text);">
          {{ range .Backups }}
            <option value="{{ .Key }}">{{ .Key }} ({{ .LastModified.Format "2006-01-02 15:04" }})</option>
          {{ end }}
        </select>
        <button type="submit">Restore</button>
        <button type="button" id="preview-backup">Preview</button>
        <label class="mode-toggle">
          <input type="checkbox" name="backup_before" value="true" checked />
          <span>Backup before restore</span>
        </label>
      </form>
      <div id="backup-contents" class="pill" style="margin-top:8px; display:none; white-space:pre-wrap;"></div>
      <form action="/action/upload" method="post" enctype="multipart/form-data" class="stack" style="margin-top:10px;">
        <input type="file" name="file" required />
        <label class="mode-toggle">
          <input type="checkbox" name="backup_before" value="true" checked />
          <span>Backup before restore</span>
        </label>
        <button type="submit">Upload + Restore</button>
      </form>
    </div>
    <script>
      (function() {
        const previewBtn = document.getElementById('preview-backup');
        const select = document.getElementById('restore-select');
        const output = document.getElementById('backup-contents');
        if (!previewBtn || !select || !output) return;
        previewBtn.addEventListener('click', async () => {
          const name = select.value;
          if (!name) {
            output.style.display = 'block';
            output.textContent = 'No backup selected.';
            return;
          }
          output.style.display = 'block';
          output.textContent = 'Loading preview...';
          try {
            const resp = await fetch('/backup/contents?name=' + encodeURIComponent(name));
            if (!resp.ok) {
              output.textContent = 'Preview failed.';
              return;
            }
            const data = await resp.json();
            const items = Array.isArray(data.items) ? data.items : [];
            if (!items.length) {
              output.textContent = 'No files listed.';
              return;
            }
            output.textContent = items.join('\n');
          } catch (err) {
            output.textContent = 'Preview failed.';
          }
        });
      })();
      (function() {
        const form = document.getElementById('groups-form');
        if (!form) return;
        form.addEventListener('submit', (e) => {
          const fields = ['group_admin','group_friend','group_guest','group_visitor'];
          const values = [];
          fields.forEach(name => {
            const el = form.querySelector('[name=\"' + name + '\"]');
            const v = (el && el.value || '').trim();
            if (v) values.push(v);
          });
          const unique = new Set(values);
          if (values.length > unique.size) {
            e.preventDefault();
            alert('Group passwords must be unique. Please use different passwords for each group.');
          }
        });
      })();
    </script>

    <div class="card" style="margin-bottom:14px;">
      <div class="title">Savegame Import / Export</div>
      <ul class="howto">
        <li>Export: click <strong>Backup Now</strong> (or wait for the schedule). Backups are stored in the S3/MinIO bucket.</li>
        <li>Download: use the Backups table or the MinIO console (port 9001) with your bucket credentials.</li>
        <li>Import: upload a <code>.tar.gz</code> or <code>.zip</code> of your savegame folder (files at archive root). The server stops, restores, and restarts.</li>
        <li>Tip: take a fresh backup before restore and avoid restores while players are online.</li>
      </ul>
    </div>

    <div class="card" style="margin-bottom:14px;">
      <div class="title">Access Groups</div>
      <form id="groups-form" action="/action/groups" method="post">
        <input type="password" name="group_admin" placeholder="Admin group password (optional)" />
        <input type="password" name="group_friend" placeholder="Friend group password (recommended)" />
        <input type="password" name="group_guest" placeholder="Guest group password (optional)" />
        <input type="password" name="group_visitor" placeholder="Visitor group password (optional)" />
        <button type="submit">Save + Restart</button>
      </form>
      <div class="pill" style="margin-top:6px;">
        Leave fields blank to keep them unchanged. Players typically join with the Friend group password.
        Passwords must be unique across groups.
      </div>
    </div>

    <div class="card">
      <div class="title">Backups</div>
      <div style="overflow-x:auto;">
        <table>
          <thead><tr><th>Name</th><th>Size</th><th>Modified</th><th>Download</th></tr></thead>
          <tbody>
          {{ if .Backups }}
            {{ range .Backups }}
              <tr>
                <td>{{ .Key }}</td>
                <td>{{ formatBytes .Size }}</td>
                <td>{{ .LastModified.Format "2006-01-02 15:04" }}</td>
                <td><a class="ghost" href="/backup/download?name={{ .Key }}">Download</a></td>
              </tr>
            {{ end }}
          {{ else }}
            <tr><td colspan="4">No backups yet.</td></tr>
          {{ end }}
          </tbody>
        </table>
      </div>
    </div>
    {{ end }}

    {{ if .LoggedIn }}
    <div class="card" style="margin-top:14px;">
      <div class="title">Steam Authentication</div>
      {{ if .SteamState }}
        <div class="status" style="margin-bottom:10px;">
          {{ if eq .SteamState.Mode "user" }}<div class="dot ok"></div>{{ else if eq .SteamState.Mode "anonymous" }}<div class="dot ok"></div>{{ else }}<div class="dot down"></div>{{ end }}
          <div>
            <div class="pill status-pill {{ if eq .SteamState.Mode "unset" }}warn{{ end }}">
              Mode: {{ .SteamState.Mode }}
              {{ if and (eq .SteamState.Mode "user") .SteamState.Username }} · User: {{ .SteamState.Username }}{{ end }}
            </div>
            {{ with .SteamState.LastError }}<div class="pill status-pill warn" style="margin-top:6px;">Last error: {{ . }}</div>{{ end }}
            {{ if eq .SteamState.Mode "unset" }}<div class="pill status-pill warn" style="margin-top:6px;">Select a login mode to start the server.</div>{{ end }}
          </div>
        </div>
      {{ end }}
      <form id="steam-mode-form" action="/action/steam-auth" method="post" style="margin-top:10px;">
        <div class="stack" style="margin-bottom:10px;">
          <label class="mode-toggle">
            <input type="radio" name="steam_mode" value="anonymous" {{if or (eq .SteamState.Mode "anonymous") (eq .SteamState.Mode "unset")}}checked{{end}} />
            <span>Anonymous</span>
          </label>
          <label class="mode-toggle">
            <input type="radio" name="steam_mode" value="user" {{if eq .SteamState.Mode "user"}}checked{{end}} />
            <span>Use Steam login</span>
          </label>
        </div>
        <div id="steam-credentials" {{if or (eq .SteamState.Mode "anonymous") (eq .SteamState.Mode "unset")}}style="display:none"{{end}}>
          <input type="text" name="steam_username" placeholder="Steam username" value="{{ .SteamState.Username }}" />
          <input type="password" name="steam_password" placeholder="Steam password" />
          <input type="text" name="steam_guard" placeholder="Steam Guard code (if prompted)" />
        </div>
        <button type="submit">Save and Restart</button>
        <div class="pill" style="margin-top:6px;">
          Choose anonymous to clear saved creds, or enter login details (with Guard code) to authenticate. Restart is automatic.
        </div>
        {{ if eq .SteamState.Mode "unset" }}<div class="pill" style="margin-top:6px; border-color:#f97316; color:#f97316;">Select a login mode to start the server.</div>{{ end }}
      </form>
      <script>
        (function() {
          const form = document.getElementById('steam-mode-form');
          if (!form) return;
          const radios = form.querySelectorAll('input[name="steam_mode"]');
          const creds = document.getElementById('steam-credentials');
          const update = () => {
            const mode = form.querySelector('input[name="steam_mode"]:checked')?.value || 'anonymous';
            creds.style.display = mode === 'user' ? 'block' : 'none';
            ['steam_username','steam_password'].forEach(id => {
              const input = form.querySelector('[name="' + id + '"]');
              if (input) input.required = (mode === 'user');
            });
          };
          radios.forEach(r => r.addEventListener('change', update));
          update();
          form.addEventListener('submit', () => {
            const mode = form.querySelector('input[name="steam_mode"]:checked')?.value || 'anonymous';
            form.action = (mode === 'anonymous') ? '/action/steam-anon' : '/action/steam-auth';
          });
        })();
      </script>
    </div>
    {{ end }}
  </div>
</body>
</html>`

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
