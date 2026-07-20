package pipeline

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/alexpermiakov/sast-triage/internal/agent"
	"github.com/alexpermiakov/sast-triage/internal/github"
	"github.com/alexpermiakov/sast-triage/internal/report"
)

type fakeReviews struct {
	posted   []github.ReviewComment
	existing []github.ReviewComment
	listErr  error
	postErr  error
}

func (f *fakeReviews) CreateReviewComment(_ context.Context, _ int, path string, line int, _, body string) error {
	if f.postErr != nil {
		return f.postErr
	}
	f.posted = append(f.posted, github.ReviewComment{Path: path, Line: line, Body: body})
	return nil
}

func (f *fakeReviews) ListReviewComments(_ context.Context, _ int) ([]github.ReviewComment, error) {
	return f.existing, f.listErr
}

func reviewItems() []report.Item {
	return []report.Item{
		{Fingerprint: "fp-x", RuleID: "go.sqli", File: "app/handlers.go", StartLine: 17,
			Verdict: agent.VerdictExploitable, Reason: "id flows unsanitized to QueryRow",
			Evidence: []string{"app/handlers.go:16"}},
		{Fingerprint: "fp-b", RuleID: "go.secret", File: "app/config.go", StartLine: 7,
			Verdict: agent.VerdictBenign, Reason: "demo credential", Evidence: []string{"app/config.go:7"}},
		{Fingerprint: "fp-u", RuleID: "go.path", File: "app/db.go", StartLine: 3,
			Verdict: agent.VerdictUncertain, Reason: "budget exhausted"},
	}
}

func reviewConfig(r ReviewCommenter) Config {
	return Config{PRNumber: 42, CommitSHA: "abc123", Reviews: r, Log: nopLog{}}
}

type nopLog struct{}

func (nopLog) Write(p []byte) (int, error) { return len(p), nil }

// Exploitable only. A bot that also comments on every uncertain finding spends
// the gate's credibility on noise — that is the whole positioning.
func TestPostReviewCommentsExploitableOnly(t *testing.T) {
	r := &fakeReviews{}
	n := postReviewComments(context.Background(), reviewConfig(r), reviewItems())
	if n != 1 || len(r.posted) != 1 {
		t.Fatalf("posted %d comments, want 1: %+v", n, r.posted)
	}
	c := r.posted[0]
	if c.Path != "app/handlers.go" || c.Line != 17 {
		t.Errorf("comment anchored at %s:%d, want app/handlers.go:17", c.Path, c.Line)
	}
	if !strings.Contains(c.Body, "id flows unsanitized to QueryRow") {
		t.Errorf("comment body missing the reason:\n%s", c.Body)
	}
	if !strings.Contains(c.Body, "app/handlers.go:16") {
		t.Errorf("comment body missing the cited evidence:\n%s", c.Body)
	}
	if !strings.Contains(c.Body, report.FingerprintMarker("fp-x")) {
		t.Errorf("comment body missing the dedupe marker:\n%s", c.Body)
	}
}

// A re-run on the same PR (a new push, a retry) must not stack duplicate
// comments on the same finding.
func TestPostReviewCommentsDedupe(t *testing.T) {
	r := &fakeReviews{existing: []github.ReviewComment{
		{Path: "app/handlers.go", Line: 17, Body: "old text " + report.FingerprintMarker("fp-x")},
	}}
	if n := postReviewComments(context.Background(), reviewConfig(r), reviewItems()); n != 0 {
		t.Errorf("posted %d comments, want 0 — the finding is already commented", n)
	}
}

// Every commenting failure degrades to a log line. Commenting must never fail
// the run, and must never mask the gate.
func TestPostReviewCommentsFailuresDegrade(t *testing.T) {
	tests := []struct {
		name string
		r    *fakeReviews
	}{
		{"listing fails", &fakeReviews{listErr: errors.New("403")}},
		{"line is outside the diff", &fakeReviews{postErr: fmt.Errorf("a.go:1: %w", github.ErrLineNotInDiff)}},
		{"token cannot comment", &fakeReviews{postErr: errors.New("403 Resource not accessible")}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if n := postReviewComments(context.Background(), reviewConfig(tt.r), reviewItems()); n != 0 {
				t.Errorf("posted = %d, want 0", n)
			}
		})
	}
}

func TestPostReviewCommentsNeedsCommitSHA(t *testing.T) {
	r := &fakeReviews{}
	cfg := reviewConfig(r)
	cfg.CommitSHA = ""
	if n := postReviewComments(context.Background(), cfg, reviewItems()); n != 0 {
		t.Errorf("posted %d comments with no SHA to anchor them to", n)
	}
}
