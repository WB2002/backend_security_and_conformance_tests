package dast_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pc/backend-boilerplate-conformance-tests/internal/dast"
	"github.com/pc/backend-boilerplate-conformance-tests/internal/runner"
	"github.com/pc/backend-boilerplate-conformance-tests/internal/types"
)

func TestDASTParsers(t *testing.T) {
	zapJSON := []byte(`{
  "site": [
    {
      "@name": "http://127.0.0.1:3000",
      "alerts": [
        {
          "pluginid": "10038",
          "alert": "Content Security Policy (CSP) Header Not Set",
          "riskcode": "2",
          "desc": "CSP header missing",
          "cweid": "693",
          "instances": [{ "uri": "http://127.0.0.1:3000/api/v1/users", "method": "GET" }]
        }
      ]
    }
  ]
}`)
	zFindings, err := dast.ParseZAPJSONOutput(zapJSON)
	if err != nil || len(zFindings) != 1 || zFindings[0].Severity != types.SeverityMedium || zFindings[0].CWE != "CWE-693" {
		t.Fatalf("zap parse failed: err=%v findings=%+v", err, zFindings)
	}

	nucleiJSONL := []byte(`{"template-id":"cors-misconfig","info":{"name":"Arbitrary Origin CORS Reflection","severity":"high","description":"Reflects Origin"},"matched-at":"http://127.0.0.1:3000/api/v1/auth/login"}` + "\n")
	nFindings, err := dast.ParseNucleiJSONLOutput(nucleiJSONL)
	if err != nil || len(nFindings) != 1 || nFindings[0].Severity != types.SeverityHigh {
		t.Fatalf("nuclei parse failed: err=%v findings=%+v", err, nFindings)
	}

	schemaOut := `
=== FAILURES ===
_ POST /api/v1/projects _
- Server error: 500 Internal Server Error
`
	sFindings := dast.ParseSchemathesisOutput(schemaOut, 1)
	if len(sFindings) != 1 || sFindings[0].Endpoint != "POST /api/v1/projects" {
		t.Fatalf("schemathesis parse failed: %+v", sFindings)
	}

	// Verify RunDASTSuite propagates tool errors and rewrites URL in ModeAuto/ModeDocker
	_, err = dast.RunDASTSuite(context.Background(), "http://127.0.0.1:3000", "/openapi.json", runner.ModeDocker, func(ctx context.Context, cmd runner.ResolvedCommand) (runner.ToolExecutionResult, error) {
		joined := strings.Join(cmd.Args, " ")
		if strings.Contains(joined, "127.0.0.1") {
			t.Fatalf("expected 127.0.0.1 rewritten to host.docker.internal in docker mode: %v", cmd.Args)
		}
		return runner.ToolExecutionResult{ExitCode: 3, Stderr: "scanner crashed"}, nil
	})
	if err == nil {
		t.Fatalf("expected RunDASTSuite to propagate scanner execution error")
	}
}

func TestAuthenticatedAndFailClosedDAST(t *testing.T) {
	// 1. Missing OpenAPI with RequireOpenAPI: true MUST produce a high-severity dast-openapi-missing finding
	srvNoSpec := httptest.NewServer(http.NotFoundHandler())
	defer srvNoSpec.Close()

	findings, err := dast.RunDASTSuiteWithOptions(context.Background(), dast.DASTOptions{
		BaseURL:        srvNoSpec.URL,
		RequireOpenAPI: true,
		Mode:           runner.ModeLocal,
	}, func(ctx context.Context, cmd runner.ResolvedCommand) (runner.ToolExecutionResult, error) {
		return runner.ToolExecutionResult{ExitCode: 0, OK: true}, nil
	})
	if err != nil || len(findings) != 1 || findings[0].ID != "dast-openapi-missing" || findings[0].Severity != types.SeverityHigh {
		t.Fatalf("expected fail-closed dast-openapi-missing finding, got %+v (err=%v)", findings, err)
	}

	// 2. Auto-discovery of /openapi.json + Bearer token header propagation to Nuclei and Schemathesis
	srvWithSpec := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/openapi.json" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"openapi":"3.0.0","info":{"title":"API","version":"1.0"}}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srvWithSpec.Close()

	var cmds []runner.ResolvedCommand
	_, err = dast.RunDASTSuiteWithOptions(context.Background(), dast.DASTOptions{
		BaseURL:        srvWithSpec.URL,
		BearerToken:    "jwt-secret-123",
		RequireOpenAPI: true,
		Mode:           runner.ModeLocal,
	}, func(ctx context.Context, cmd runner.ResolvedCommand) (runner.ToolExecutionResult, error) {
		cmds = append(cmds, cmd)
		return runner.ToolExecutionResult{ExitCode: 0, OK: true}, nil
	})
	if err != nil || len(cmds) != 3 {
		t.Fatalf("expected all 3 DAST tools (nuclei, zap, schemathesis) to run via auto-discovered /api/openapi.json, got %d (err=%v)", len(cmds), err)
	}
	if !strings.Contains(strings.Join(cmds[0].Args, " "), "Authorization: Bearer jwt-secret-123") ||
		!strings.Contains(strings.Join(cmds[2].Args, " "), "Authorization: Bearer jwt-secret-123") {
		t.Fatalf("expected Bearer token injected into nuclei and schemathesis args: %v / %v", cmds[0].Args, cmds[2].Args)
	}

	// 3. Verify ZAP Docker invocation receives ZAP_AUTH_HEADER env vars and uses isolated 0700/0777 workdir
	var dockerCmds []runner.ResolvedCommand
	_, err = dast.RunDASTSuiteWithOptions(context.Background(), dast.DASTOptions{
		BaseURL:        srvWithSpec.URL,
		BearerToken:    "jwt-secret-123",
		RequireOpenAPI: true,
		Mode:           runner.ModeDocker,
	}, func(ctx context.Context, cmd runner.ResolvedCommand) (runner.ToolExecutionResult, error) {
		dockerCmds = append(dockerCmds, cmd)
		// Check ZAP workdir permissions while it exists during execution
		if len(dockerCmds) == 2 {
			for i, a := range cmd.Args {
				if a == "-v" && i+1 < len(cmd.Args) && strings.HasSuffix(cmd.Args[i+1], ":/zap/wrk:rw") {
					hostDir := strings.TrimSuffix(cmd.Args[i+1], ":/zap/wrk:rw")
					dirInfo, statErr := os.Stat(hostDir)
					if statErr != nil {
						t.Fatalf("failed to stat ZAP outDir %s: %v", hostDir, statErr)
					}
					if dirInfo.Mode().Perm()&0o007 != 0o007 {
						t.Fatalf("expected ZAP outDir %s to be 0777, got %o", hostDir, dirInfo.Mode().Perm())
					}
					parentInfo, statErr := os.Stat(filepath.Dir(hostDir))
					if statErr != nil {
						t.Fatalf("failed to stat ZAP parentDir: %v", statErr)
					}
					if parentInfo.Mode().Perm() != 0o700 {
						t.Fatalf("expected ZAP parentDir to be 0700, got %o", parentInfo.Mode().Perm())
					}
				}
			}
		}
		return runner.ToolExecutionResult{ExitCode: 0, OK: true}, nil
	})
	if err != nil || len(dockerCmds) != 3 {
		t.Fatalf("expected 3 docker DAST commands, got %d (err=%v)", len(dockerCmds), err)
	}
	zapArgs := strings.Join(dockerCmds[1].Args, " ")
	if !strings.Contains(zapArgs, "-e ZAP_AUTH_HEADER=Authorization") ||
		!strings.Contains(zapArgs, "-e ZAP_AUTH_HEADER_VALUE=Bearer jwt-secret-123") {
		t.Fatalf("expected ZAP_AUTH_HEADER env vars in docker ZAP command, got: %v", dockerCmds[1].Args)
	}
}

func TestDiscoverOpenAPIURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/swagger/doc.json" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"swagger":"2.0","info":{"title":"Legacy"}}`))
			return
		}
		if r.URL.Path == "/openapi.json" {
			// 200 OK but not an OpenAPI/Swagger document
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<html>not found</html>`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	got := dast.DiscoverOpenAPIURL(srv.URL)
	if got != "/swagger/doc.json" {
		t.Fatalf("expected /swagger/doc.json, got %q", got)
	}

	srvEmpty := httptest.NewServer(http.NotFoundHandler())
	defer srvEmpty.Close()
	if got := dast.DiscoverOpenAPIURL(srvEmpty.URL); got != "" {
		t.Fatalf("expected empty string when no spec exists, got %q", got)
	}
}
