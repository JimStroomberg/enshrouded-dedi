package main

import (
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestParseContainerPath(t *testing.T) {
	name, action, ok := parseContainerPath("/containers/game/json")
	if !ok || name != "game" || action != "json" {
		t.Fatalf("unexpected parse result: %q %q %t", name, action, ok)
	}
	for _, path := range []string{"/containers/game", "/containers/game/json/extra", "/containers//json"} {
		if _, _, ok := parseContainerPath(path); ok {
			t.Fatalf("expected %q to be rejected", path)
		}
	}
}

func TestAllowedActionsAreNarrow(t *testing.T) {
	allowed := []struct{ method, action string }{
		{http.MethodGet, "json"},
		{http.MethodPost, "start"},
		{http.MethodPost, "stop"},
		{http.MethodPost, "restart"},
	}
	for _, test := range allowed {
		if !allowedAction(test.method, test.action) {
			t.Fatalf("expected %s %s to be allowed", test.method, test.action)
		}
	}
	for _, test := range []struct{ method, action string }{
		{http.MethodGet, "start"},
		{http.MethodPost, "json"},
		{http.MethodDelete, "json"},
		{http.MethodPost, "remove"},
	} {
		if allowedAction(test.method, test.action) {
			t.Fatalf("expected %s %s to be rejected", test.method, test.action)
		}
	}
}

func TestControllerRejectsWrongContainerAndToken(t *testing.T) {
	const token = "controller-test-token-0123456789abcdef"
	c := &controller{container: "game", token: token, logger: log.New(io.Discard, "", 0)}

	wrongToken := httptest.NewRequest(http.MethodGet, "/containers/game/json", nil)
	wrongToken.Header.Set("Authorization", "Bearer wrong")
	recorder := httptest.NewRecorder()
	c.handleContainer(recorder, wrongToken)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token got %d", recorder.Code)
	}

	wrongContainer := httptest.NewRequest(http.MethodGet, "/containers/other/json", nil)
	wrongContainer.Header.Set("Authorization", "Bearer "+token)
	recorder = httptest.NewRecorder()
	c.handleContainer(recorder, wrongContainer)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("wrong container got %d", recorder.Code)
	}
}
