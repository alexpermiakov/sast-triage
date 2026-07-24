package pipeline

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/alexpermiakov/sast-triage/internal/agent"
	"github.com/alexpermiakov/sast-triage/internal/scope"
)

// TestRunDiffScope: on a diff-scoped run only findings in changed files reach
// the LLM. The rest are not deferred, not cached, not verdicted — they are out
// of scope, and this run says nothing about them.
func TestRunDiffScope(t *testing.T) {
	repo := sampleRepo(t)
	dir := t.TempDir()

	// Touch one file: only its finding (the config.go secret) is in scope.
	// Appending keeps lines 1-7 where the fixture pins them.
	appendLine(t, filepath.Join(repo, "app/config.go"), "\n// touched by this change\n")
	git(t, repo, "commit", "-qam", "change config")

	cfg := baseConfig(t, dir)
	cfg.RepoRoot = repo
	cfg.Scope = scope.Diff
	cfg.BaseRef = "main"
	cfg.Client = &fakeClient{responses: []*agent.Response{
		textResp(`{"verdict": "benign", "reason": "sample credential in demo code", "evidence": ["app/config.go:7"]}`),
	}}

	s, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if s.Scanned != 3 {
		t.Errorf("Scanned = %d, want 3 (the SARIF held three findings)", s.Scanned)
	}
	if s.Total != 1 || s.Benign != 1 {
		t.Errorf("summary = %+v, want exactly the one finding in a changed file", s)
	}
	if s.Deferred != 0 {
		t.Errorf("Deferred = %d — out-of-scope findings are not deferred work, they are another run's job", s.Deferred)
	}

	// The gate sees one benign finding and nothing else: a change confined to
	// files with no exploitable findings must not fail, whatever the untriaged
	// backlog elsewhere in the repo looks like.
	if fail, _ := Gate(ModeEnforce, DefaultFailOn, s); fail {
		t.Error("diff-scoped run gated on findings outside the change")
	}
}

// TestRunDiffScopeEmptyChange: a change touching no scanned file triages
// nothing and costs nothing. The LLM client is nil, so any attempt to triage
// would fail the run rather than pass silently.
func TestRunDiffScopeEmptyChange(t *testing.T) {
	repo := sampleRepo(t)
	dir := t.TempDir()
	appendLine(t, filepath.Join(repo, "README.md"), "docs only\n")
	git(t, repo, "add", ".")
	git(t, repo, "commit", "-qm", "docs")

	cfg := baseConfig(t, dir)
	cfg.RepoRoot = repo
	cfg.Scope = scope.Diff
	cfg.BaseRef = "main"
	cfg.Client = nil

	s, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if s.Total != 0 || s.TokensUsed != 0 {
		t.Errorf("summary = %+v, want an empty, free run", s)
	}
}

func TestRunDiffScopeBadBaseRef(t *testing.T) {
	cfg := baseConfig(t, t.TempDir())
	cfg.RepoRoot = sampleRepo(t)
	cfg.Scope = scope.Diff
	cfg.BaseRef = "origin/does-not-exist"
	if _, err := Run(context.Background(), cfg); err == nil {
		t.Error("unknown base ref accepted; a typo would silently scope the run to nothing")
	}
}

// sampleRepo copies testdata/sampleapp into a git repo whose main branch holds
// the pristine tree, leaving HEAD on a feature branch for the caller to modify.
func sampleRepo(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	root := t.TempDir()
	err := filepath.Walk(sampleRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(sampleRoot, path)
		dst := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(dst, data, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "README.md"), []byte("sample\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	git(t, root, "init", "-q")
	git(t, root, "config", "user.email", "test@example.com")
	git(t, root, "config", "user.name", "test")
	git(t, root, "add", ".")
	git(t, root, "commit", "-qm", "base")
	git(t, root, "branch", "-M", "main")
	git(t, root, "checkout", "-qb", "feature")
	return root
}

func git(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

func appendLine(t *testing.T, path, text string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(text); err != nil {
		t.Fatal(err)
	}
}
