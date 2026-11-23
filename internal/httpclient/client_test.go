package httpclient_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pc/backend-boilerplate-conformance-tests/internal/config"
	"github.com/pc/backend-boilerplate-conformance-tests/internal/httpclient"
)

func TestConfigAndHTTPClient(t *testing.T) {
	cfg := config.LoadConfig(func(k string) string {
		if k == "BASE_URL" {
			return "http://127.0.0.1:4000/"
		}
		return ""
	})
	if cfg.BaseURL != "http://127.0.0.1:4000" {
		t.Fatalf("expected trimmed BaseURL, got %s", cfg.BaseURL)
	}

	ip0 := httpclient.ClientIPFor("04-auth-sessions-csrf.spec.ts", 0)
	ip1 := httpclient.ClientIPFor("04-auth-sessions-csrf", 1)
	if ip0 != "198.51.100.40" || ip1 != "198.51.100.41" {
		t.Fatalf("unexpected deterministic RFC 5737 IPs: %s, %s", ip0, ip1)
	}

	var gotForwardedFor, gotCSRF, gotCookie, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotForwardedFor = r.Header.Get("X-Forwarded-For")
		gotCSRF = r.Header.Get("X-CSRF-Token")
		gotCookie = r.Header.Get("Cookie")
		gotAuth = r.Header.Get("Authorization")
		http.SetCookie(w, &http.Cookie{Name: "csrf_token", Value: "csrf-xyz"})
		http.SetCookie(w, &http.Cookie{Name: "session_id", Value: "sess-1"})
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := httpclient.NewClient("04-auth-sessions-csrf", srv.URL, 0)
	resp, err := client.Request(http.MethodPost, "/login", httpclient.RequestOptions{
		BearerToken: "tok-123",
		JSONBody:    map[string]string{"email": "a@b.c"},
	})
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("first request failed: %v", err)
	}
	if gotForwardedFor != "198.51.100.40" || gotAuth != "Bearer tok-123" {
		t.Fatalf("headers mismatch: xff=%s auth=%s", gotForwardedFor, gotAuth)
	}

	_, err = client.Request(http.MethodPost, "/action", httpclient.RequestOptions{CSRF: true})
	if err != nil {
		t.Fatalf("second request failed: %v", err)
	}
	if gotCSRF != "csrf-xyz" || gotCookie == "" {
		t.Fatalf("expected csrf header and cookies, got csrf=%s cookie=%s", gotCSRF, gotCookie)
	}
}
