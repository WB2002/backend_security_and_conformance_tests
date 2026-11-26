package sast

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pc/backend-boilerplate-conformance-tests/internal/types"
)

func writeFixtureFile(t *testing.T, root, relPath, content string) {
	t.Helper()
	fullPath := filepath.Join(root, filepath.FromSlash(relPath))
	if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", fullPath, err)
	}
	if err := os.WriteFile(fullPath, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", fullPath, err)
	}
}

func assertHasLeakRule(t *testing.T, findings []types.SecurityFinding, ruleID string, wantSev types.Severity, wantCWE string) {
	t.Helper()
	for _, f := range findings {
		if f.ID == ruleID {
			if f.Category != types.CategoryResourceLeak {
				t.Errorf("rule %s: got category %q, want %q", ruleID, f.Category, types.CategoryResourceLeak)
			}
			if f.Tool != "leak-sast" {
				t.Errorf("rule %s: got tool %q, want %q", ruleID, f.Tool, "leak-sast")
			}
			if f.Severity != wantSev {
				t.Errorf("rule %s: got severity %q, want %q", ruleID, f.Severity, wantSev)
			}
			if f.CWE != wantCWE {
				t.Errorf("rule %s: got CWE %q, want %q", ruleID, f.CWE, wantCWE)
			}
			if f.Line <= 0 {
				t.Errorf("rule %s: expected positive line number, got %d", ruleID, f.Line)
			}
			return
		}
	}
	t.Errorf("expected finding with ID %q (sev=%s, cwe=%s), got findings: %+v", ruleID, wantSev, wantCWE, findings)
}

func assertNoLeakRule(t *testing.T, findings []types.SecurityFinding, ruleID string) {
	t.Helper()
	for _, f := range findings {
		if f.ID == ruleID {
			t.Errorf("expected NO finding with ID %q on clean code, got: %+v", ruleID, f)
		}
	}
}

func TestScanStaticResourceLeaks(t *testing.T) {
	t.Run("GoASTLeaks", func(t *testing.T) {
		vulnDir := t.TempDir()
		writeFixtureFile(t, vulnDir, "go.mod", "module example.com/vuln\n\ngo 1.24\n")
		writeFixtureFile(t, vulnDir, "leaks.go", `package vuln

import (
	"context"
	"database/sql"
	"net/http"
	"time"
)

func unclosedHTTPGet() error {
	resp, err := http.Get("https://example.com")
	if err != nil {
		return err
	}
	_ = resp.StatusCode
	return nil
}

func unclosedHTTPDo(client *http.Client, req *http.Request) error {
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	_ = res.StatusCode
	return nil
}

func unclosedSQLRows(db *sql.DB) error {
	rows, err := db.Query("SELECT 1")
	if err != nil {
		return err
	}
	for rows.Next() {
	}
	return rows.Err()
}

func timeAfterInLoop(ch <-chan struct{}) {
	for {
		select {
		case <-ch:
			return
		case <-time.After(time.Second):
		}
	}
}

func discardedCancel(parent context.Context) context.Context {
	ctx, _ := context.WithTimeout(parent, 5*time.Second)
	return ctx
}

func missingHTTPTimeouts() (*http.Server, *http.Client) {
	srv := &http.Server{Addr: ":8080"}
	cli := &http.Client{}
	return srv, cli
}
`)

		findings, err := ScanStaticResourceLeaks(vulnDir, types.LangGo)
		if err != nil {
			t.Fatalf("ScanStaticResourceLeaks(vuln Go) failed: %v", err)
		}
		assertHasLeakRule(t, findings, "leak-go-unclosed-resp-body", types.SeverityHigh, "CWE-772")
		assertHasLeakRule(t, findings, "leak-go-unclosed-sql-rows", types.SeverityHigh, "CWE-772")
		assertHasLeakRule(t, findings, "leak-go-time-after-in-loop", types.SeverityHigh, "CWE-400")
		assertHasLeakRule(t, findings, "leak-go-discarded-context-cancel", types.SeverityHigh, "CWE-404")
		assertHasLeakRule(t, findings, "leak-go-http-missing-timeouts", types.SeverityMedium, "CWE-400")

		cleanDir := t.TempDir()
		writeFixtureFile(t, cleanDir, "go.mod", "module example.com/clean\n\ngo 1.24\n")
		writeFixtureFile(t, cleanDir, "clean.go", `package clean

import (
	"context"
	"database/sql"
	"net/http"
	"time"
)

func closedHTTPGet() error {
	resp, err := http.Get("https://example.com")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

func closedHTTPDo(client *http.Client, req *http.Request) error {
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	return nil
}

func closedSQLRows(db *sql.DB) error {
	rows, err := db.Query("SELECT 1")
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
	}
	return rows.Err()
}

func tickerInLoop(ch <-chan struct{}) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ch:
			return
		case <-t.C:
		}
	}
}

func properCancel(parent context.Context) error {
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	_ = ctx
	return nil
}

func properHTTPTimeouts() (*http.Server, *http.Client, *http.Client) {
	srv := &http.Server{
		Addr:              ":8080",
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       15 * time.Second,
	}
	cli1 := &http.Client{Timeout: 10 * time.Second}
	cli2 := &http.Client{Transport: &http.Transport{}}
	return srv, cli1, cli2
}

type retrier struct{}

func (retrier) Do(fn func() error) error { return fn() }

func nonResourceQueryAndSingleReturnDo(r *http.Request, retry retrier, fn func() error) error {
	q := r.URL.Query()
	_ = q.Get("id")
	err := retry.Do(fn)
	return err
}
`)

		cleanFindings, err := ScanStaticResourceLeaks(cleanDir, types.LangGo)
		if err != nil {
			t.Fatalf("ScanStaticResourceLeaks(clean Go) failed: %v", err)
		}
		if len(cleanFindings) != 0 {
			t.Errorf("expected 0 findings on clean Go code, got %d: %+v", len(cleanFindings), cleanFindings)
		}
	})

	t.Run("TypeScriptLeaks", func(t *testing.T) {
		vulnDir := t.TempDir()
		writeFixtureFile(t, vulnDir, "src/cache.ts", `
const sessionCache = new Map<string, any>();

export function storeSession(id: string, data: any) {
  sessionCache.set(id, data);
}
`)
		writeFixtureFile(t, vulnDir, "src/interval.ts", `
export function startPoller() {
  setInterval(() => {
    console.log("tick");
  }, 1000);
}
`)
		writeFixtureFile(t, vulnDir, "src/stream.ts", `
import fs from "fs";

export function forwardFile(src: string, dst: string) {
  const rs = fs.createReadStream(src);
  const ws = fs.createWriteStream(dst);
  rs.pipe(ws);
}
`)

		findings, err := ScanStaticResourceLeaks(vulnDir, types.LangTypeScript)
		if err != nil {
			t.Fatalf("ScanStaticResourceLeaks(vuln TS) failed: %v", err)
		}
		assertHasLeakRule(t, findings, "leak-ts-unbounded-module-collection", types.SeverityHigh, "CWE-400")
		assertHasLeakRule(t, findings, "leak-ts-uncleaned-interval-or-listener", types.SeverityMedium, "CWE-404")
		assertHasLeakRule(t, findings, "leak-ts-unsafe-stream-pipe", types.SeverityMedium, "CWE-404")

		cleanDir := t.TempDir()
		writeFixtureFile(t, cleanDir, "src/cache.ts", `
const sessionCache = new Map<string, any>();

export function storeSession(id: string, data: any) {
  sessionCache.set(id, data);
  if (sessionCache.size > 1000) {
    sessionCache.delete(id);
  }
}
`)
		writeFixtureFile(t, cleanDir, "src/interval.ts", `
export function startPoller() {
  const timer = setInterval(() => {
    console.log("tick");
  }, 1000);
  return () => clearInterval(timer);
}
`)
		writeFixtureFile(t, cleanDir, "src/stream.ts", `
import fs from "fs";
import { pipeline } from "stream/promises";

export async function forwardFile(src: string, dst: string) {
  await pipeline(fs.createReadStream(src), fs.createWriteStream(dst));
}
`)

		cleanFindings, err := ScanStaticResourceLeaks(cleanDir, types.LangTypeScript)
		if err != nil {
			t.Fatalf("ScanStaticResourceLeaks(clean TS) failed: %v", err)
		}
		assertNoLeakRule(t, cleanFindings, "leak-ts-unbounded-module-collection")
		assertNoLeakRule(t, cleanFindings, "leak-ts-uncleaned-interval-or-listener")
		assertNoLeakRule(t, cleanFindings, "leak-ts-unsafe-stream-pipe")
	})

	t.Run("PythonLeaks", func(t *testing.T) {
		vulnDir := t.TempDir()
		writeFixtureFile(t, vulnDir, "app/service.py", `
import asyncio
import functools
from functools import lru_cache
import httpx

def read_data(path):
    f = open(path, "r")
    return f.read()

async def fire_and_forget(coro):
    asyncio.create_task(coro)

@lru_cache(maxsize=None)
def compute_user_profile(user_id):
    return {"id": user_id}
`)

		findings, err := ScanStaticResourceLeaks(vulnDir, types.LangPython)
		if err != nil {
			t.Fatalf("ScanStaticResourceLeaks(vuln Python) failed: %v", err)
		}
		assertHasLeakRule(t, findings, "leak-py-unmanaged-resource", types.SeverityHigh, "CWE-772")
		assertHasLeakRule(t, findings, "leak-py-untracked-async-task", types.SeverityMedium, "CWE-404")
		assertHasLeakRule(t, findings, "leak-py-unbounded-lru-cache", types.SeverityHigh, "CWE-400")

		cleanDir := t.TempDir()
		writeFixtureFile(t, cleanDir, "app/service.py", `
import asyncio
from functools import lru_cache

background_tasks = set()

def read_data(path):
    with open(path, "r") as f:
        return f.read()

async def tracked_task(coro):
    task = asyncio.create_task(coro)
    background_tasks.add(task)
    task.add_done_callback(background_tasks.discard)

@lru_cache(maxsize=128)
def compute_user_profile(user_id):
    return {"id": user_id}
`)
		writeFixtureFile(t, cleanDir, "app/config.py", `
import functools

@functools.cache
def get_settings():
    return {"env": "prod"}
`)

		cleanFindings, err := ScanStaticResourceLeaks(cleanDir, types.LangPython)
		if err != nil {
			t.Fatalf("ScanStaticResourceLeaks(clean Python) failed: %v", err)
		}
		assertNoLeakRule(t, cleanFindings, "leak-py-unmanaged-resource")
		assertNoLeakRule(t, cleanFindings, "leak-py-untracked-async-task")
		assertNoLeakRule(t, cleanFindings, "leak-py-unbounded-lru-cache")
	})

	t.Run("ElixirLeaks", func(t *testing.T) {
		vulnDir := t.TempDir()
		writeFixtureFile(t, vulnDir, "lib/worker.ex", `
defmodule MyApp.Worker do
  def parse_key(raw) do
    String.to_atom(raw)
  end

  def start_unsupervised(fun) do
    spawn(fun)
  end

  def init_table do
    :ets.new(:unbounded_cache, [:named_table, :public])
  end
end
`)

		findings, err := ScanStaticResourceLeaks(vulnDir, types.LangElixir)
		if err != nil {
			t.Fatalf("ScanStaticResourceLeaks(vuln Elixir) failed: %v", err)
		}
		assertHasLeakRule(t, findings, "leak-ex-dynamic-atom-creation", types.SeverityCritical, "CWE-400")
		assertHasLeakRule(t, findings, "leak-ex-unsupervised-spawn-or-ets", types.SeverityHigh, "CWE-400")

		cleanDir := t.TempDir()
		writeFixtureFile(t, cleanDir, "lib/worker.ex", `
defmodule MyApp.Worker do
  def parse_key(raw) do
    String.to_existing_atom(raw)
  end

  def start_supervised(fun) do
    Task.Supervisor.start_child(MyApp.TaskSupervisor, fun)
  end

  def init_and_cleanup do
    t = :ets.new(:ephemeral_cache, [:set, :private])
    :ets.delete(t)
  end
end
`)

		cleanFindings, err := ScanStaticResourceLeaks(cleanDir, types.LangElixir)
		if err != nil {
			t.Fatalf("ScanStaticResourceLeaks(clean Elixir) failed: %v", err)
		}
		assertNoLeakRule(t, cleanFindings, "leak-ex-dynamic-atom-creation")
		assertNoLeakRule(t, cleanFindings, "leak-ex-unsupervised-spawn-or-ets")
	})
}

func TestScanStaticResourceLeaks_CleanOnSelfRepo(t *testing.T) {
	findings, err := ScanStaticResourceLeaks("../..", types.LangGo)
	if err != nil {
		t.Fatalf("ScanStaticResourceLeaks on self repo failed: %v", err)
	}
	for _, f := range findings {
		if f.Severity == types.SeverityHigh || f.Severity == types.SeverityCritical {
			t.Errorf("self-repo has High/Critical leak finding: %+v", f)
		}
	}
	for _, f := range findings {
		if f.ID == "leak-go-http-missing-timeouts" {
			t.Errorf("self-repo has unhardened http.Server/http.Client: %+v", f)
		}
	}
}
