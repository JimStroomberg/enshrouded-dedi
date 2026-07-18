package main

import (
	"html/template"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/sessions"
)

func TestValidateUIConfigRejectsDefaults(t *testing.T) {
	cfg := validTestConfig()
	cfg.AdminPass = "changeme"
	if err := validateUIConfig(cfg); err == nil {
		t.Fatal("expected default admin password to be rejected")
	}
	cfg = validTestConfig()
	cfg.SessionCrypt = "too-short"
	if err := validateUIConfig(cfg); err == nil {
		t.Fatal("expected invalid encryption key to be rejected")
	}
}

func TestLoginLimiterBlocksAndResets(t *testing.T) {
	limiter := newLoginLimiter(2, time.Minute)
	now := time.Now()
	if !limiter.allow("127.0.0.1", now) {
		t.Fatal("fresh address should be allowed")
	}
	limiter.failure("127.0.0.1", now)
	limiter.failure("127.0.0.1", now)
	if limiter.allow("127.0.0.1", now) {
		t.Fatal("address should be throttled")
	}
	limiter.success("127.0.0.1")
	if !limiter.allow("127.0.0.1", now) {
		t.Fatal("successful login should reset throttle")
	}
}

func TestCSRFRejectsStateChangingRequest(t *testing.T) {
	srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{}`)
	}))
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("username=admin&password=correct-password"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recorder := httptest.NewRecorder()
	srv.handler().ServeHTTP(recorder, req)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("got status %d, want %d", recorder.Code, http.StatusForbidden)
	}
}

func TestAdminPageDoesNotRenderGamePassword(t *testing.T) {
	const gamePassword = "must-never-appear-in-html"
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/status":
			io.WriteString(w, `{"name":"game","state":"running","running":true}`)
		case "/steam/state":
			io.WriteString(w, `{"mode":"anonymous","chosen":true}`)
		case "/server/config":
			io.WriteString(w, `{"name":"game","server_password":"`+gamePassword+`","game_settings":{}}`)
		default:
			io.WriteString(w, `[]`)
		}
	})
	srv := newTestServer(t, upstream)

	authReq := httptest.NewRequest(http.MethodGet, "/", nil)
	authRecorder := httptest.NewRecorder()
	session, err := srv.store.Get(authReq, "enshrouded-ui")
	if err != nil {
		t.Fatal(err)
	}
	session.Values["auth"] = true
	if err := session.Save(authReq, authRecorder); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, cookie := range authRecorder.Result().Cookies() {
		req.AddCookie(cookie)
	}
	recorder := httptest.NewRecorder()
	srv.handler().ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("got status %d", recorder.Code)
	}
	if strings.Contains(recorder.Body.String(), gamePassword) {
		t.Fatal("game password was rendered into HTML")
	}
}

func TestBackupClientAddsInternalToken(t *testing.T) {
	seen := ""
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get("Authorization")
		io.WriteString(w, `{"name":"game","running":true}`)
	}))
	defer upstream.Close()

	srv := newTestServer(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srv.cfg.BackupAPI = upstream.URL
	if _, err := srv.fetchStatus(t.Context()); err != nil {
		t.Fatal(err)
	}
	if seen != "Bearer "+srv.cfg.BackupToken {
		t.Fatalf("unexpected authorization header %q", seen)
	}
}

func TestFetchBackupsDecodesMinioObjectFields(t *testing.T) {
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `[{"name":"backup-20260718-200000.tar.gz","size":1234,"lastModified":"2026-07-18T20:00:00Z"}]`)
	})
	srv := newTestServer(t, upstream)
	items, err := srv.fetchBackups(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Key != "backup-20260718-200000.tar.gz" || items[0].Size != 1234 || items[0].LastModified.IsZero() {
		t.Fatalf("unexpected backups: %#v", items)
	}
}

func TestBackupClientReturnsUpstreamErrorsAndTimeouts(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			time.Sleep(100 * time.Millisecond)
			io.WriteString(w, `{}`)
			return
		}
		http.Error(w, "failed", http.StatusBadGateway)
	}))
	defer upstream.Close()
	srv := newTestServer(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srv.cfg.BackupAPI = upstream.URL
	if _, err := srv.fetchStatus(t.Context()); err == nil {
		t.Fatal("expected upstream status error")
	}
	srv.client.Timeout = 10 * time.Millisecond
	srv.cfg.BackupAPI = upstream.URL + "/slow/.."
	request, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, upstream.URL+"/slow", nil)
	if _, err := srv.client.Do(request); err == nil {
		t.Fatal("expected client timeout")
	}
}

func newTestServer(t *testing.T, upstream http.Handler) *Server {
	t.Helper()
	upstreamServer := httptest.NewServer(upstream)
	t.Cleanup(upstreamServer.Close)
	cfg := validTestConfig()
	cfg.BackupAPI = upstreamServer.URL
	store := sessions.NewCookieStore([]byte(cfg.SessionSecret), []byte(cfg.SessionCrypt))
	store.Options = &sessions.Options{Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode}
	tmpl := template.Must(template.New("page").Funcs(template.FuncMap{
		"formatBytes": formatBytes,
		"join":        strings.Join,
	}).Parse(pageTemplate))
	return &Server{
		cfg:         cfg,
		store:       store,
		client:      &http.Client{Timeout: time.Second, Transport: &tokenTransport{base: http.DefaultTransport, token: cfg.BackupToken}},
		logger:      log.New(io.Discard, "", 0),
		tmpl:        tmpl,
		a2sEnabled:  false,
		a2sCacheTTL: time.Second,
		loginGuard:  newLoginLimiter(5, time.Minute),
	}
}

func validTestConfig() UIConfig {
	return UIConfig{
		AdminUser:     "admin",
		AdminPass:     "correct-password",
		SessionSecret: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		SessionCrypt:  "0123456789abcdef0123456789abcdef",
		CSRFKey:       "abcdef0123456789abcdef0123456789",
		BackupToken:   "internal-token-0123456789abcdef0123456789",
		SessionHours:  1,
	}
}
