package sast

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

//go:embed rules/*.yaml
var embeddedSemgrepRules embed.FS

// WriteEmbeddedSemgrepRules extracts embedded Semgrep YAML rule packs into
// filepath.Join(dir, "rules") and returns that rules directory path.
func WriteEmbeddedSemgrepRules(dir string) (string, error) {
	if dir == "" {
		return "", fmt.Errorf("destination directory is required")
	}
	rulesDir := filepath.Join(dir, "rules")
	if err := os.MkdirAll(rulesDir, 0o755); err != nil {
		return "", fmt.Errorf("create embedded semgrep rules dir: %w", err)
	}
	entries, err := fs.ReadDir(embeddedSemgrepRules, "rules")
	if err != nil {
		return "", fmt.Errorf("read embedded semgrep rules: %w", err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		data, err := embeddedSemgrepRules.ReadFile("rules/" + entry.Name())
		if err != nil {
			return "", fmt.Errorf("read embedded rule %s: %w", entry.Name(), err)
		}
		dest := filepath.Join(rulesDir, entry.Name())
		if err := os.WriteFile(dest, data, 0o644); err != nil {
			return "", fmt.Errorf("write embedded rule %s: %w", dest, err)
		}
	}
	return rulesDir, nil
}
