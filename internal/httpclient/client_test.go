package httpclient_test

import (
	"bufio"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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

func TestClient_DoesNotHangOn101SwitchingProtocols(t *testing.T) {
	hold := make(chan struct{})
	defer close(hold)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Fatal("ResponseWriter does not implement http.Hijacker")
		}
		conn, bufrw, err := hj.Hijack()
		if err != nil {
			t.Fatalf("hijack failed: %v", err)
		}
		defer conn.Close()
		_, _ = bufrw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		_ = bufrw.Flush()
		<-hold
	}))
	defer srv.Close()

	client := httpclient.NewClient("ws-probe", srv.URL, 0)
	client.HTTPClient.Timeout = 2 * time.Second

	done := make(chan error, 1)
	var resp *httpclient.Response
	go func() {
		var err error
		resp, err = client.Request(http.MethodGet, "/socket.io/?EIO=4&transport=websocket", httpclient.RequestOptions{})
		done <- err
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("expected 101 response without timeout/error, got %v", err)
		}
		if resp.StatusCode != http.StatusSwitchingProtocols {
			t.Fatalf("expected 101, got %d", resp.StatusCode)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("client.Request hung reading 101 Switching Protocols body")
	}
	_ = bufio.NewReader
}
