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
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
)

// UIConfig holds env configuration.
type UIConfig struct {
	StackName     string
	AdminUser     string
	AdminPass     string
	SessionSecret string
	BackupAPI     string
	SessionHours  int
}

type Server struct {
	cfg    UIConfig
	store  *sessions.CookieStore
	client *http.Client
	logger *log.Logger
	tmpl   *template.Template
}

type statusResponse struct {
	ID      string      `json:"id"`
	Name    string      `json:"name"`
	State   string      `json:"state"`
	Running bool        `json:"running"`
	Health  interface{} `json:"health"`
}

type backupItem struct {
	Key          string    `json:"Key"`
	Size         int64     `json:"Size"`
	LastModified time.Time `json:"LastModified"`
}

func main() {
	cfg := UIConfig{
		StackName:     getenv("STACK_NAME", "Enshrouded Stack"),
		AdminUser:     getenv("UI_ADMIN_USERNAME", "admin"),
		AdminPass:     getenv("UI_ADMIN_PASSWORD", "changeme"),
		SessionSecret: getenv("UI_SESSION_SECRET", "change-me"),
		BackupAPI:     getenv("BACKUP_API_URL", "http://backup:7000"),
		SessionHours:  atoiEnv("UI_SESSION_HOURS", 24),
	}

	store := sessions.NewCookieStore([]byte(cfg.SessionSecret))
	store.Options = &sessions.Options{MaxAge: cfg.SessionHours * 3600, HttpOnly: true, SameSite: http.SameSiteLaxMode, Path: "/"}

	tmpl := template.Must(template.New("page").Funcs(template.FuncMap{
		"formatBytes": formatBytes,
	}).Parse(pageTemplate))

	srv := &Server{
		cfg:    cfg,
		store:  store,
		client: &http.Client{Timeout: 10 * time.Second},
		logger: log.New(os.Stdout, "ui ", log.LstdFlags|log.Lmsgprefix),
		tmpl:   tmpl,
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
	var backups []backupItem
	if loggedIn {
		backups, _ = s.fetchBackups(r.Context())
	}

	data := map[string]interface{}{
		"StackName": s.cfg.StackName,
		"Status":    status,
		"Backups":   backups,
		"LoggedIn":  loggedIn,
		"Message":   r.URL.Query().Get("msg"),
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
	body := map[string]string{"name": name}
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
	if err != nil {
		http.Error(w, "failed to fetch status", http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
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

const pageTemplate = `<!doctype html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{{ .StackName }} | Enshrouded</title>
  <style>
    :root {
      --bg: radial-gradient(circle at 10% 20%, #0f172a, #0b1021 45%, #060913 100%);
      --card: rgba(255,255,255,0.04);
      --accent: #8b5cf6;
      --text: #e5e7eb;
      --muted: #9ca3af;
      --border: rgba(255,255,255,0.08);
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      background: var(--bg);
      color: var(--text);
      font-family: "Space Grotesk", "Inter", "Segoe UI", system-ui, -apple-system, sans-serif;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 24px;
    }
    .shell {
      width: 100%;
      max-width: 960px;
      background: linear-gradient(135deg, rgba(255,255,255,0.06), rgba(255,255,255,0.02));
      border: 1px solid var(--border);
      border-radius: 18px;
      padding: 28px;
      box-shadow: 0 30px 80px rgba(0,0,0,0.45);
      backdrop-filter: blur(6px);
    }
    header {
      display: flex;
      justify-content: space-between;
      gap: 12px;
      flex-wrap: wrap;
      align-items: center;
      margin-bottom: 16px;
    }
    h1 { margin: 0; font-size: 22px; letter-spacing: 0.01em; }
    .badge { padding: 6px 10px; border-radius: 10px; background: var(--card); border: 1px solid var(--border); font-size: 12px; color: var(--muted); }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 14px; }
    .card { background: var(--card); border: 1px solid var(--border); border-radius: 14px; padding: 16px; }
    .title { font-size: 14px; text-transform: uppercase; letter-spacing: 0.08em; color: var(--muted); margin-bottom: 10px; }
    .status { display: flex; align-items: center; gap: 8px; font-size: 16px; }
    .dot { width: 10px; height: 10px; border-radius: 999px; }
    .dot.ok { background: #34d399; box-shadow: 0 0 0 6px rgba(52,211,153,0.15); }
    .dot.down { background: #f97316; box-shadow: 0 0 0 6px rgba(249,115,22,0.15); }
    form { margin: 0; }
    button, .ghost { appearance: none; border: 1px solid var(--border); background: rgba(255,255,255,0.06); color: var(--text); padding: 10px 12px; border-radius: 10px; cursor: pointer; font-weight: 600; letter-spacing: 0.01em; transition: 0.2s ease; }
    button:hover, .ghost:hover { border-color: var(--accent); box-shadow: 0 10px 30px rgba(139,92,246,0.25); }
    .stack { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; }
    .msg { margin-top: 12px; color: var(--accent); font-weight: 600; }
    table { width: 100%; border-collapse: collapse; font-size: 14px; }
    th, td { padding: 8px 6px; text-align: left; color: var(--muted); }
    th { text-transform: uppercase; letter-spacing: 0.05em; font-size: 12px; }
    tr:nth-child(odd) td { background: rgba(255,255,255,0.02); }
    input[type="text"], input[type="password"], input[type="file"] { width: 100%; padding: 10px 12px; border-radius: 10px; border: 1px solid var(--border); background: rgba(255,255,255,0.04); color: var(--text); margin-bottom: 10px; }
    .pill { font-size: 12px; padding: 4px 10px; border-radius: 999px; border: 1px solid var(--border); color: var(--muted); }
  </style>
</head>
<body>
  <div class="shell">
    <header>
      <div>
        <div class="pill">{{ .StackName }}</div>
        <h1>Enshrouded Status</h1>
      </div>
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
    </header>

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
            </div>
          </div>
        {{ else }}
          <div class="status"><div class="dot down"></div><div>Unknown (backup API unreachable)</div></div>
        {{ end }}
      </div>
      <div class="card">
        <div class="title">Actions</div>
        <div class="stack">
          <form action="/action/restart" method="post"><button type="submit">Restart</button></form>
          <form action="/action/update" method="post"><button type="submit">Trigger Update</button></form>
          <form action="/action/backup" method="post"><button type="submit">Backup Now</button></form>
          <a class="ghost" href="/logs">Download Logs</a>
        </div>
      </div>
    </div>

    {{ if .LoggedIn }}
    <div class="card" style="margin-bottom:14px;">
      <div class="title">Restore</div>
      <form action="/action/restore" method="post" class="stack">
        <select name="name" style="padding:10px 12px; border-radius:10px; border:1px solid var(--border); background:rgba(255,255,255,0.04); color:var(--text);">
          {{ range .Backups }}
            <option value="{{ .Key }}">{{ .Key }} ({{ .LastModified.Format "2006-01-02 15:04" }})</option>
          {{ end }}
        </select>
        <button type="submit">Restore</button>
      </form>
      <form action="/action/upload" method="post" enctype="multipart/form-data" class="stack" style="margin-top:10px;">
        <input type="file" name="file" required />
        <button type="submit">Upload + Restore</button>
      </form>
    </div>

    <div class="card">
      <div class="title">Backups</div>
      <div style="overflow-x:auto;">
        <table>
          <thead><tr><th>Name</th><th>Size</th><th>Modified</th></tr></thead>
          <tbody>
          {{ if .Backups }}
            {{ range .Backups }}
              <tr><td>{{ .Key }}</td><td>{{ formatBytes .Size }}</td><td>{{ .LastModified.Format "2006-01-02 15:04" }}</td></tr>
            {{ end }}
          {{ else }}
            <tr><td colspan="3">No backups yet.</td></tr>
          {{ end }}
          </tbody>
        </table>
      </div>
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
