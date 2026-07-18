package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newTestExecutor(t *testing.T) (*ToolExecutor, string) {
	t.Helper()
	root := t.TempDir()
	write := func(rel, content string) {
		t.Helper()
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	var big strings.Builder
	for i := 1; i <= 250; i++ {
		fmt.Fprintf(&big, "line %d\n", i)
	}
	write("big.go", big.String())
	write("app/handlers.go", "package app\n\nfunc handle() {} // needle\n")
	write("app/other.txt", "needle in text\n")
	write(".git/config", "needle in git\n")
	write("bin.dat", "needle\x00binary")

	exec, err := NewToolExecutor(root)
	if err != nil {
		t.Fatal(err)
	}
	return exec, root
}

func run(t *testing.T, exec *ToolExecutor, tool string, args map[string]any) (string, error) {
	t.Helper()
	raw, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	return exec.Execute(tool, raw)
}

func TestReadFileCapsAt200Lines(t *testing.T) {
	exec, _ := newTestExecutor(t)
	out, err := run(t, exec, "read_file", map[string]any{"path": "big.go"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "1: line 1\n") || !strings.Contains(out, "200: line 200\n") {
		t.Error("expected numbered lines 1..200")
	}
	if strings.Contains(out, "201: ") {
		t.Error("read_file exceeded the 200-line cap")
	}
	if !strings.Contains(out, "start_line=201") {
		t.Error("truncation note should say how to continue")
	}

	out, err = run(t, exec, "read_file", map[string]any{"path": "big.go", "start_line": 201})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "250: line 250\n") || strings.Contains(out, "truncated") {
		t.Errorf("paged read wrong:\n%s", out)
	}
}

func TestCustomCaps(t *testing.T) {
	exec, _ := newTestExecutor(t)
	exec.readLines = 100
	exec.grepMatches = 10

	out, err := run(t, exec, "read_file", map[string]any{"path": "big.go"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "100: line 100\n") || strings.Contains(out, "101: ") {
		t.Error("read_file ignored the custom 100-line cap")
	}
	if !strings.Contains(out, "truncated at 100 lines") || !strings.Contains(out, "start_line=101") {
		t.Errorf("truncation note must reflect the custom cap:\n%s", out)
	}

	out, err = run(t, exec, "grep_repo", map[string]any{"pattern": "^line "})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(out, "big.go:"); got != 10 {
		t.Errorf("got %d matches, want custom cap of 10", got)
	}
	if !strings.Contains(out, "truncated at 10 matches") {
		t.Errorf("truncation note must reflect the custom cap:\n%s", out)
	}
}

func TestToolDefsAdvertiseCaps(t *testing.T) {
	defs := toolDefs(100, 25)
	if !strings.Contains(defs[0].Description, "at most 100 lines") {
		t.Errorf("read_file description = %q", defs[0].Description)
	}
	if !strings.Contains(defs[1].Description, "at most 25 matches") {
		t.Errorf("grep_repo description = %q", defs[1].Description)
	}
}

func TestReadFileErrors(t *testing.T) {
	exec, root := newTestExecutor(t)
	for name, args := range map[string]map[string]any{
		"missing file":     {"path": "nope.go"},
		"absolute path":    {"path": "/etc/hosts"},
		"traversal":        {"path": "../../etc/hosts"},
		"sneaky traversal": {"path": "app/../../outside.go"},
		"empty path":       {"path": ""},
		"binary file":      {"path": "bin.dat"},
		"beyond eof":       {"path": "app/handlers.go", "start_line": 999},
	} {
		if _, err := run(t, exec, "read_file", args); err == nil {
			t.Errorf("%s: want error", name)
		}
	}

	// Symlink escaping the root must be rejected even though the literal
	// path looks repo-relative.
	outside := filepath.Join(filepath.Dir(root), "outside.txt")
	if err := os.WriteFile(outside, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "link.txt")); err != nil {
		t.Fatal(err)
	}
	if _, err := run(t, exec, "read_file", map[string]any{"path": "link.txt"}); err == nil {
		t.Error("symlink escape: want error")
	}
}

func TestGrepRepo(t *testing.T) {
	exec, _ := newTestExecutor(t)

	out, err := run(t, exec, "grep_repo", map[string]any{"pattern": "needle"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "app/handlers.go:3:") || !strings.Contains(out, "app/other.txt:1:") {
		t.Errorf("missing expected matches:\n%s", out)
	}
	if strings.Contains(out, ".git") || strings.Contains(out, "bin.dat") {
		t.Errorf(".git and binary files must be skipped:\n%s", out)
	}

	out, _ = run(t, exec, "grep_repo", map[string]any{"pattern": "needle", "glob": "*.go"})
	if strings.Contains(out, "other.txt") {
		t.Errorf("glob filter ignored:\n%s", out)
	}

	out, _ = run(t, exec, "grep_repo", map[string]any{"pattern": "absent-xyzzy"})
	if !strings.Contains(out, "no matches") {
		t.Errorf("want no-matches marker, got:\n%s", out)
	}

	if _, err := run(t, exec, "grep_repo", map[string]any{"pattern": "([bad"}); err == nil {
		t.Error("invalid regexp: want error")
	}

	out, err = run(t, exec, "grep_repo", map[string]any{"pattern": "^line "})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(out, "big.go:"); got != defaultMaxGrepMatches {
		t.Errorf("got %d matches, want cap of %d", got, defaultMaxGrepMatches)
	}
	if !strings.Contains(out, "narrow your pattern") {
		t.Error("truncated grep must tell the model to narrow the pattern")
	}
}

func TestUnknownTool(t *testing.T) {
	exec, _ := newTestExecutor(t)
	if _, err := exec.Execute("write_file", json.RawMessage(`{}`)); err == nil {
		t.Error("unknown tool: want error")
	}
}
