// Package scope narrows a finding set to the files a change touched. Scope is
// decided by the caller (the trigger event), never inferred from cache state:
// a pull_request run asks for diff scope, everything else asks for full.
//
// The known hole, stated here because it must also be stated in the README: a
// change in Foo.java can make a PRE-EXISTING finding in Bar.java exploitable,
// and diff scope never sees it. Nothing keyed on changed files can. That is
// what the scheduled full-scope run is for — the two are a pair, not
// alternatives. Semgrep's baseline mode has the same hole.
package scope

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path"
	"strings"

	"github.com/alexpermiakov/sast-triage/internal/sarif"
)

// Modes.
const (
	Full = "full"
	Diff = "diff"
)

// Valid reports whether s names a scope mode.
func Valid(s string) bool { return s == Full || s == Diff }

// ChangedFiles returns the repo-relative paths that differ between baseRef and
// the working tree, using the merge base (`baseRef...HEAD`) so unrelated commits
// landing on the base branch after the PR forked do not widen the scope.
//
// Renames are reported at their new path only: a finding at the old path no
// longer exists to triage.
func ChangedFiles(ctx context.Context, repoRoot, baseRef string) ([]string, error) {
	if baseRef == "" {
		return nil, fmt.Errorf("diff scope needs a base ref (e.g. -base-ref origin/main)")
	}
	// --diff-filter=d drops deletions: a finding in a deleted file cannot be
	// triaged, and its evidence regions are gone too.
	cmd := exec.CommandContext(ctx, "git", "-C", repoRoot, "diff",
		"--name-only", "--diff-filter=d", baseRef+"...HEAD")
	out, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return nil, fmt.Errorf("git diff against %s: %w: %s", baseRef, err, strings.TrimSpace(string(ee.Stderr)))
		}
		return nil, fmt.Errorf("git diff against %s: %w", baseRef, err)
	}

	var files []string
	for _, line := range strings.Split(string(out), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			files = append(files, path.Clean(line))
		}
	}
	return files, nil
}

// Filter keeps only findings whose flagged file is in files. It is pure; the
// git call above is the only I/O in this package.
//
// A finding is kept on its FLAGGED location alone, not on its taint trace: a
// trace hop through a changed file does not make the finding this change's
// responsibility, and matching on hops would drag most of the backlog into
// scope on any change to a shared helper.
func Filter(findings []sarif.Finding, files []string) []sarif.Finding {
	changed := make(map[string]struct{}, len(files))
	for _, f := range files {
		changed[f] = struct{}{}
	}
	kept := make([]sarif.Finding, 0, len(findings))
	for _, f := range findings {
		if _, ok := changed[path.Clean(f.File)]; ok {
			kept = append(kept, f)
		}
	}
	return kept
}
