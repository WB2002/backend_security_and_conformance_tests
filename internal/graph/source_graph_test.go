package graph_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pc/backend-boilerplate-conformance-tests/internal/graph"
	"github.com/pc/backend-boilerplate-conformance-tests/internal/types"
)

func hasEdge(edges []types.GraphEdge, from, to string) bool {
	for _, e := range edges {
		if e.From == from && e.To == to {
			return true
		}
	}
	return false
}

func TestPolyglotSourceGraphBuilder(t *testing.T) {
	t.Run("TypeScript/JS ESM imports, NodeNext .js->.ts, and tsconfig path aliases", func(t *testing.T) {
		g := graph.BuildSourceGraphFromFiles(map[string]string{
			"src/auth/auth.service.ts": `
				import { UsersService } from '../users/users.service.js';
				import { signJwt } from '@/crypto/jwt';
			`,
			"src/users/users.service.ts": `
				import { AuthService } from '../auth/auth.service.js';
			`,
			"src/crypto/jwt.ts": `
				import crypto from 'node:crypto';
				export const signJwt = () => {};
			`,
		}, graph.SourceGraphOptions{
			Language:      types.LangTypeScript,
			TSPathAliases: map[string][]string{"@/*": {"src/*"}},
		})

		if !hasEdge(g.Edges, "src/auth/auth.service.ts", "src/users/users.service.ts") ||
			!hasEdge(g.Edges, "src/auth/auth.service.ts", "src/crypto/jwt.ts") ||
			!hasEdge(g.Edges, "src/users/users.service.ts", "src/auth/auth.service.ts") {
			t.Fatalf("missing expected TS edges in %+v", g.Edges)
		}
	})

	t.Run("Go native go/parser package imports with go.mod prefix", func(t *testing.T) {
		g := graph.BuildSourceGraphFromFiles(map[string]string{
			"internal/auth/service.go": `
				package auth
				import (
					"fmt"
					"github.com/acme/app/internal/users"
				)
			`,
			"internal/users/repo.go": `
				package users
				import "github.com/acme/app/internal/auth"
			`,
		}, graph.SourceGraphOptions{
			Language:     types.LangGo,
			GoModuleName: "github.com/acme/app",
		})

		if !hasEdge(g.Edges, "internal/auth/service.go", "internal/users/repo.go") ||
			!hasEdge(g.Edges, "internal/users/repo.go", "internal/auth/service.go") {
			t.Fatalf("missing expected Go edges in %+v", g.Edges)
		}
	})

	t.Run("Python absolute and relative from-imports", func(t *testing.T) {
		g := graph.BuildSourceGraphFromFiles(map[string]string{
			"app/auth/service.py": `
import os
from app.users import repository
from .tokens import verify_token
`,
			"app/auth/tokens.py": `
from app.users.repository import get_user
`,
			"app/users/repository.py": `
from app.auth.service import authenticate
`,
		}, graph.SourceGraphOptions{Language: types.LangPython})

		if !hasEdge(g.Edges, "app/auth/service.py", "app/users/repository.py") ||
			!hasEdge(g.Edges, "app/auth/service.py", "app/auth/tokens.py") ||
			!hasEdge(g.Edges, "app/users/repository.py", "app/auth/service.py") {
			t.Fatalf("missing expected Python edges in %+v", g.Edges)
		}
	})

	t.Run("Elixir defmodule index, multi-alias {A, B}, import/use, and remote calls", func(t *testing.T) {
		g := graph.BuildSourceGraphFromFiles(map[string]string{
			"lib/my_app/auth/guardian.ex": `
defmodule MyApp.Auth.Guardian do
  use Joken.Config
  alias MyApp.Accounts.{User, Permissions}
  def verify(token), do: MyApp.Accounts.User.find(token)
end
`,
			"lib/my_app/accounts/user.ex": `
defmodule MyApp.Accounts.User do
  import MyApp.Auth.Guardian
  def find(id), do: id
end
`,
			"lib/my_app/accounts/permissions.ex": `
defmodule MyApp.Accounts.Permissions do
  def check(), do: :ok
end
`,
		}, graph.SourceGraphOptions{Language: types.LangElixir})

		if !hasEdge(g.Edges, "lib/my_app/auth/guardian.ex", "lib/my_app/accounts/user.ex") ||
			!hasEdge(g.Edges, "lib/my_app/auth/guardian.ex", "lib/my_app/accounts/permissions.ex") ||
			!hasEdge(g.Edges, "lib/my_app/accounts/user.ex", "lib/my_app/auth/guardian.ex") {
			t.Fatalf("missing expected Elixir edges in %+v", g.Edges)
		}
	})

	t.Run("Python consecutive imports and Elixir parent context non-false-edge", func(t *testing.T) {
		pyG := graph.BuildSourceGraphFromFiles(map[string]string{
			"app/a.py": "import os\nimport app.b\nfrom app.c import (\n    helper,\n)\n",
			"app/b.py": "x = 1\n",
			"app/c.py": "def helper(): pass\n",
		}, graph.SourceGraphOptions{Language: types.LangPython})
		if !hasEdge(pyG.Edges, "app/a.py", "app/b.py") || !hasEdge(pyG.Edges, "app/a.py", "app/c.py") {
			t.Fatalf("expected consecutive/multiline python imports to resolve, got %+v", pyG.Edges)
		}

		exG := graph.BuildSourceGraphFromFiles(map[string]string{
			"lib/my_app/accounts.ex":      "defmodule MyApp.Accounts do\nend\n",
			"lib/my_app/accounts/user.ex": "defmodule MyApp.Accounts.User do\nend\n",
			"lib/my_app/caller.ex":        "defmodule MyApp.Caller do\n  alias MyApp.Accounts.{User}\nend\n",
		}, graph.SourceGraphOptions{Language: types.LangElixir})
		if hasEdge(exG.Edges, "lib/my_app/caller.ex", "lib/my_app/accounts.ex") {
			t.Fatalf("expected multi-alias not to create false edge to parent context MyApp.Accounts: %+v", exG.Edges)
		}
		if !hasEdge(exG.Edges, "lib/my_app/caller.ex", "lib/my_app/accounts/user.ex") {
			t.Fatalf("expected multi-alias edge to user.ex: %+v", exG.Edges)
		}
	})
}

func TestBuildSourceGraphFromDir_SkipsDotDirsTestsAndDeclarations(t *testing.T) {
	tmp := t.TempDir()
	mustWrite := func(rel, content string) {
		full := filepath.Join(tmp, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	mustWrite("tsconfig.json", `{"compilerOptions":{"paths":{"@/*":["./src/*"]}}}`)
	mustWrite("src/app.module.ts", `import { AuthService } from '@/auth/auth.service'; export class AppModule {}`)
	mustWrite("src/auth/auth.service.ts", `export class AuthService {}`)
	mustWrite("src/auth/tests/auth.service.spec.ts", `import { AppModule } from '@/app.module'; import { AuthService } from '@/auth/auth.service';`)
	mustWrite(".tsd-emit/app.module.d.ts", `import { AuthService } from './auth/auth.service';`)
	mustWrite(".worktrees/old/src/cycle.ts", `import './cycle';`)
	mustWrite("coverage/prettify.js", `function prettify() {}`)

	g, err := graph.BuildSourceGraphFromDir(tmp, types.LangTypeScript)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(g.Nodes) != 2 {
		t.Fatalf("expected 2 production nodes, got %d: %+v", len(g.Nodes), g.Nodes)
	}
}

func TestBuildSourceGraphFromDir_DoesNotSkipDotRootDir(t *testing.T) {
	dotRoot := filepath.Join(t.TempDir(), ".dot-target")
	srcDir := filepath.Join(dotRoot, "src")
	if err := os.MkdirAll(srcDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "app.ts"), []byte("export const x = 1;"), 0o644); err != nil {
		t.Fatal(err)
	}

	g, err := graph.BuildSourceGraphFromDir(dotRoot, types.LangTypeScript)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(g.Nodes) != 1 {
		t.Fatalf("expected 1 node when targetDir basename starts with '.', got %d", len(g.Nodes))
	}
}

func TestLoadTSConfigChain_JSONCCommentsTrailingCommasAndCyclicExtends(t *testing.T) {
	tmp := t.TempDir()
	mustWrite := func(rel, content string) {
		full := filepath.Join(tmp, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// Base config extends a missing node_modules package and has comments + URL inside string + trailing commas
	mustWrite("tsconfig.base.json", `{
  // Inherit from missing package config
  "extends": "@tsconfig/node20/tsconfig.json",
  /* Block comment with "quotes" and // line */
  "compilerOptions": {
    "baseUrl": "./src",
    "paths": {
      "@app/*": ["modules/*"],
      "@shared/*": ["./src/shared/*",],
    },
  },
}`)
	mustWrite("tsconfig.json", `{
  // Local override
  "extends": "./tsconfig.base.json",
  "compilerOptions": {
    "sourceRoot": "https://example.com/src//not-a-comment",
    "paths": {
      "@app/*": ["modules/*"],
    },
  },
}`)
	mustWrite("src/modules/users/user.service.ts", `export const getUser = () => "ok";`)
	mustWrite("src/shared/logger.ts", `export const log = (m: string) => m;`)
	mustWrite("src/controllers/user.controller.ts", `
import express from 'express';
import { getUser } from '@app/users/user.service';
import { log } from 'shared/logger';
export const handle = () => [express, getUser(), log('hi')];
`)

	stripped := graph.StripJSONC([]byte(`{"url": "https://a.test//path", /* c */ "k": [1, 2,],}`))
	if string(stripped) == "" {
		t.Fatalf("StripJSONC returned empty output")
	}

	baseURL, paths := graph.LoadTSConfigChain(tmp)
	if baseURL != "src" {
		t.Fatalf("expected baseURL 'src', got %q", baseURL)
	}
	if len(paths["@app/*"]) == 0 || len(paths["@shared/*"]) == 0 {
		t.Fatalf("expected inherited and local paths, got %+v", paths)
	}

	g, err := graph.BuildSourceGraphFromDir(tmp, types.LangTypeScript)
	if err != nil {
		t.Fatalf("BuildSourceGraphFromDir failed: %v", err)
	}
	if !hasEdge(g.Edges, "src/controllers/user.controller.ts", "src/modules/users/user.service.ts") {
		t.Fatalf("expected @app/* alias edge, got %+v", g.Edges)
	}
	if !hasEdge(g.Edges, "src/controllers/user.controller.ts", "src/shared/logger.ts") {
		t.Fatalf("expected baseUrl-relative edge to src/shared/logger.ts, got %+v", g.Edges)
	}

	var foundExpress bool
	for _, n := range g.Nodes {
		if n.ID == "src/controllers/user.controller.ts" {
			for _, ext := range n.ExternalImports {
				if ext == "express" {
					foundExpress = true
				}
			}
		}
	}
	if !foundExpress {
		t.Fatalf("expected ExternalImports to include 'express', got nodes %+v", g.Nodes)
	}

	// Cyclic extends: a.json -> b.json -> a.json must terminate cleanly
	cycDir := t.TempDir()
	_ = os.WriteFile(filepath.Join(cycDir, "tsconfig.json"), []byte(`{"extends":"./b.json","compilerOptions":{"baseUrl":"./src"}}`), 0o644)
	_ = os.WriteFile(filepath.Join(cycDir, "b.json"), []byte(`{"extends":"./tsconfig.json","compilerOptions":{"paths":{"@x/*":["x/*"]}}}`), 0o644)
	cycBase, cycPaths := graph.LoadTSConfigChain(cycDir)
	if cycBase != "src" || len(cycPaths["@x/*"]) == 0 {
		t.Fatalf("expected cyclic tsconfig chain to terminate and preserve options, got base=%q paths=%+v", cycBase, cycPaths)
	}
}

func TestPythonSrcLayoutAndElixirAliasAs(t *testing.T) {
	pyG := graph.BuildSourceGraphFromFiles(map[string]string{
		"src/mypkg/users/service.py": `
import requests
from mypkg.users import repo
`,
		"src/mypkg/users/repo.py": `
def fetch():
    return []
`,
	}, graph.SourceGraphOptions{Language: types.LangPython})

	if !hasEdge(pyG.Edges, "src/mypkg/users/service.py", "src/mypkg/users/repo.py") {
		t.Fatalf("expected Python src/ layout edge to src/mypkg/users/repo.py, got %+v", pyG.Edges)
	}
	var foundRequests bool
	for _, n := range pyG.Nodes {
		if n.ID == "src/mypkg/users/service.py" {
			for _, ext := range n.ExternalImports {
				if ext == "requests" {
					foundRequests = true
				}
			}
		}
	}
	if !foundRequests {
		t.Fatalf("expected ExternalImports to contain 'requests', got %+v", pyG.Nodes)
	}

	exG := graph.BuildSourceGraphFromFiles(map[string]string{
		"lib/my_app/accounts/service.ex": `
defmodule MyApp.Accounts.Service do
  use Joken.Config
  alias MyApp.Accounts.UserRepo, as: Repo
  def load(id), do: Repo.get(id)
end
`,
		"lib/my_app/accounts/user_repo.ex": `
defmodule MyApp.Accounts.UserRepo do
  def get(id), do: id
end
`,
	}, graph.SourceGraphOptions{Language: types.LangElixir})

	if !hasEdge(exG.Edges, "lib/my_app/accounts/service.ex", "lib/my_app/accounts/user_repo.ex") {
		t.Fatalf("expected Elixir alias-as edge to lib/my_app/accounts/user_repo.ex, got %+v", exG.Edges)
	}
	var foundJoken bool
	for _, n := range exG.Nodes {
		if n.ID == "lib/my_app/accounts/service.ex" {
			for _, ext := range n.ExternalImports {
				if ext == "joken" {
					foundJoken = true
				}
			}
		}
	}
	if !foundJoken {
		t.Fatalf("expected Elixir ExternalImports to contain 'joken', got %+v", exG.Nodes)
	}
}


