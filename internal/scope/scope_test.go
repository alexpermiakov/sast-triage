package scope

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"

	"github.com/alexpermiakov/sast-triage/internal/sarif"
)

func TestFilter(t *testing.T) {
	findings := []sarif.Finding{
		{RuleID: "sqli", File: "app/handlers.go", StartLine: 17},
		{RuleID: "secret", File: "app/config.go", StartLine: 7},
		{RuleID: "xss", File: "web/render.go", StartLine: 42},
		{RuleID: "path", File: "./app/db.go", StartLine: 3}, // uncleaned SARIF uri
	}

	tests := []struct {
		name    string
		changed []string
		want    []string
	}{
		{
			name:    "keeps findings in changed files only",
			changed: []string{"app/handlers.go", "docs/README.md"},
			want:    []string{"sqli"},
		},
		{
			name:    "matches after path cleaning on both sides",
			changed: []string{"app/db.go"},
			want:    []string{"path"},
		},
		{
			name:    "no changed files means nothing in scope",
			changed: nil,
			want:    nil,
		},
		{
			name:    "every file changed keeps everything",
			changed: []string{"app/handlers.go", "app/config.go", "web/render.go", "app/db.go"},
			want:    []string{"sqli", "secret", "xss", "path"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Filter(findings, tt.changed)
			var ids []string
			for _, f := range got {
				ids = append(ids, f.RuleID)
			}
			if !slices.Equal(ids, tt.want) {
				t.Errorf("Filter kept %v, want %v", ids, tt.want)
			}
		})
	}
}

// TestFilterIgnoresTraceHops pins the decision that scope follows the FLAGGED
// location only. Matching on taint-trace hops would drag most of a backlog into
// scope the moment anyone edits a shared helper.
func TestFilterIgnoresTraceHops(t *testing.T) {
	findings := []sarif.Finding{{
		RuleID: "sqli",
		File:   "app/handlers.go",
		Trace:  []sarif.TraceHop{{File: "app/db.go", Line: 12}},
	}}
	if got := Filter(findings, []string{"app/db.go"}); len(got) != 0 {
		t.Errorf("a change to a trace-hop file pulled the finding into scope: %+v", got)
	}
}

func TestChangedFiles(t *testing.T) {
	repo := newRepo(t)

	// Base commit on main.
	write(t, repo, "app/handlers.go", "package app\n")
	write(t, repo, "app/config.go", "package app\n")
	git(t, repo, "add", ".")
	git(t, repo, "commit", "-m", "base")
	git(t, repo, "branch", "-M", "main")

	// Feature branch: one file modified, one added, one deleted.
	git(t, repo, "checkout", "-b", "feature")
	write(t, repo, "app/handlers.go", "package app\n\nfunc H() {}\n")
	write(t, repo, "web/render.go", "package web\n")
	git(t, repo, "rm", "-q", "app/config.go")
	git(t, repo, "add", ".")
	git(t, repo, "commit", "-m", "feature")

	got, err := ChangedFiles(context.Background(), repo, "main")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"app/handlers.go", "web/render.go"}
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Errorf("ChangedFiles = %v, want %v (deleted files excluded: nothing left to triage)", got, want)
	}
}

// TestChangedFilesUsesMergeBase pins the `...` semantics: commits landing on
// the base branch after the feature branch forked must not widen the scope, or
// every PR gets billed for whatever else merged that morning.
func TestChangedFilesUsesMergeBase(t *testing.T) {
	repo := newRepo(t)
	write(t, repo, "a.go", "package a\n")
	git(t, repo, "add", ".")
	git(t, repo, "commit", "-m", "base")
	git(t, repo, "branch", "-M", "main")

	git(t, repo, "checkout", "-b", "feature")
	write(t, repo, "feature.go", "package a\n")
	git(t, repo, "add", ".")
	git(t, repo, "commit", "-m", "feature")

	// Someone else's work lands on main after the fork point.
	git(t, repo, "checkout", "main")
	write(t, repo, "unrelated.go", "package a\n")
	git(t, repo, "add", ".")
	git(t, repo, "commit", "-m", "unrelated")
	git(t, repo, "checkout", "feature")

	got, err := ChangedFiles(context.Background(), repo, "main")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []string{"feature.go"}) {
		t.Errorf("ChangedFiles = %v, want [feature.go]; unrelated.go landed on main after the fork point", got)
	}
}

func TestChangedFilesErrors(t *testing.T) {
	repo := newRepo(t)
	write(t, repo, "a.go", "package a\n")
	git(t, repo, "add", ".")
	git(t, repo, "commit", "-m", "base")

	if _, err := ChangedFiles(context.Background(), repo, ""); err == nil {
		t.Error("empty base ref accepted; diff scope without a base silently triages nothing")
	}
	if _, err := ChangedFiles(context.Background(), repo, "origin/nope"); err == nil {
		t.Error("unknown base ref accepted; a typo would silently narrow scope to nothing")
	}
}

func newRepo(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	dir := t.TempDir()
	git(t, dir, "init", "-q")
	git(t, dir, "config", "user.email", "test@example.com")
	git(t, dir, "config", "user.name", "test")
	return dir
}

func git(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

func write(t *testing.T, dir, name, content string) {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
