package pipeline

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alexpermiakov/sast-triage/internal/agent"
	"github.com/alexpermiakov/sast-triage/internal/cache"
)

const (
	fixtureSARIF = "../../testdata/findings.sarif"
	sampleRoot   = "../../testdata/sampleapp"
)

type fakeClient struct {
	mu        sync.Mutex
	responses []*agent.Response
	calls     int
}

func (c *fakeClient) Complete(_ context.Context, _ agent.Request) (*agent.Response, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	if len(c.responses) == 0 {
		return nil, fmt.Errorf("fake client: script exhausted")
	}
	r := c.responses[0]
	c.responses = c.responses[1:]
	return r, nil
}

func textResp(text string) *agent.Response {
	return &agent.Response{
		Content:      []agent.Block{{Type: "text", Text: text}},
		StopReason:   "end_turn",
		InputTokens:  100,
		OutputTokens: 50,
	}
}

type fakeIssues struct {
	titles []string
}

func (f *fakeIssues) CreateIssue(_ context.Context, title, _ string, _ []string) (int, error) {
	f.titles = append(f.titles, title)
	return 76 + len(f.titles), nil
}

func baseConfig(t *testing.T, dir string) Config {
	t.Helper()
	return Config{
		SARIFPath:  fixtureSARIF,
		CachePath:  filepath.Join(dir, "triage-cache.json"),
		RepoRoot:   sampleRoot,
		ReportPath: filepath.Join(dir, "triage-report.md"),
		Model:      "test-model",
		Parallel:   1, // deterministic response ordering for the scripted client
		Now:        func() time.Time { return time.Date(2026, 7, 17, 2, 0, 0, 0, time.UTC) },
	}
}

func TestRunFullThenIncremental(t *testing.T) {
	dir := t.TempDir()
	cfg := baseConfig(t, dir)
	// Severity order: SQLi first, test-file finding short-circuits (no LLM),
	// then the context-free secret. Two scripted calls.
	cfg.Client = &fakeClient{responses: []*agent.Response{
		textResp(`{"verdict": "exploitable", "reason": "id flows unsanitized to QueryRow", "evidence": ["app/handlers.go:16", "app/handlers.go:17-18"]}`),
		textResp(`{"verdict": "benign", "reason": "sample credential in demo code, not a live secret", "evidence": ["app/config.go:7"]}`),
	}}
	issues := &fakeIssues{}
	cfg.Issues = issues

	s, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if s.Total != 3 || s.Benign != 2 || s.Exploitable != 1 || s.Uncertain != 0 {
		t.Errorf("summary = %+v", s)
	}
	if s.Cached != 0 || s.Fresh != 3 {
		t.Errorf("cache accounting = %+v", s)
	}
	if s.NewExploitable != 1 {
		t.Errorf("NewExploitable = %d, want 1 (fresh exploitable verdicts trip the PR gate)", s.NewExploitable)
	}
	if s.IssuesFiled != 1 || len(issues.titles) != 1 || !strings.Contains(issues.titles[0], "app/handlers.go:17") {
		t.Errorf("issues = %+v, summary %+v", issues.titles, s)
	}

	c, err := cache.Load(cfg.CachePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Entries) != 3 {
		t.Fatalf("cache entries = %d, want all verdict classes stored", len(c.Entries))
	}
	sqli, ok := c.Entries["0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9_0"]
	if !ok || sqli.Verdict != "exploitable" || sqli.IssueRef != 77 {
		t.Errorf("sqli entry = %+v", sqli)
	}
	if !strings.HasPrefix(sqli.CodeHash, "sha256:") || sqli.DecidedAt != "2026-07-17T02:00:00Z" {
		t.Errorf("sqli entry metadata = %+v", sqli)
	}
	testEntry := c.Entries["9d8c7b6a5f4e3d2c1b0a99887766554433221100ffeeddccbbaa998877665544_0"]
	if testEntry.Verdict != "benign" || testEntry.Model != "rule:short-circuit" {
		t.Errorf("test-file entry = %+v", testEntry)
	}

	md, err := os.ReadFile(cfg.ReportPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(md), "## Proposed suppressions") || !strings.Contains(string(md), "## Exploitable") {
		t.Errorf("report missing sections:\n%s", md)
	}

	// Second run: everything cached, no client needed, no duplicate issue.
	cfg2 := baseConfig(t, dir)
	issues2 := &fakeIssues{}
	cfg2.Issues = issues2
	s2, err := Run(context.Background(), cfg2)
	if err != nil {
		t.Fatal(err)
	}
	if s2.Cached != 3 || s2.Fresh != 0 || s2.TokensUsed != 0 {
		t.Errorf("incremental summary = %+v", s2)
	}
	if s2.NewExploitable != 0 {
		t.Errorf("NewExploitable = %d on a cached run; cache hits must never trip the PR gate", s2.NewExploitable)
	}
	if len(issues2.titles) != 0 {
		t.Errorf("issue filed twice: %v", issues2.titles)
	}
}

func TestRunBudgetDefersLowSeverity(t *testing.T) {
	dir := t.TempDir()
	cfg := baseConfig(t, dir)
	cfg.MaxFindings = 1
	cfg.Client = &fakeClient{responses: []*agent.Response{
		textResp(`{"verdict": "exploitable", "reason": "unsanitized flow", "evidence": ["app/handlers.go:16"]}`),
	}}

	s, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if s.Deferred != 1 || s.Uncertain != 1 {
		t.Errorf("summary = %+v, want the secret finding deferred as uncertain", s)
	}

	c, _ := cache.Load(cfg.CachePath)
	if len(c.Entries) != 2 {
		t.Errorf("cache entries = %d; deferred findings must NOT be cached", len(c.Entries))
	}
	md, _ := os.ReadFile(cfg.ReportPath)
	if !strings.Contains(string(md), "deferred: run budget") {
		t.Error("report must mark deferred findings")
	}
}

func TestRunTransportErrorNotCached(t *testing.T) {
	dir := t.TempDir()
	cfg := baseConfig(t, dir)
	cfg.Client = &fakeClient{} // every call fails
	s, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatal(err) // finding-level failures must not fail the run
	}
	if s.Uncertain != 2 {
		t.Errorf("summary = %+v, want both LLM findings uncertain", s)
	}
	c, _ := cache.Load(cfg.CachePath)
	if len(c.Entries) != 1 {
		t.Errorf("cache entries = %d; only the short-circuit may be cached after transport failures", len(c.Entries))
	}
}

func TestRunNeedsClientOnlyWhenWorkRemains(t *testing.T) {
	dir := t.TempDir()
	cfg := baseConfig(t, dir)
	if _, err := Run(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "ANTHROPIC_API_KEY") {
		t.Errorf("uncached findings with no client: want key error, got %v", err)
	}
}

func TestRunMissingSARIF(t *testing.T) {
	dir := t.TempDir()
	cfg := baseConfig(t, dir)
	cfg.SARIFPath = filepath.Join(dir, "absent.sarif")
	if _, err := Run(context.Background(), cfg); err == nil {
		t.Error("missing SARIF: want error")
	}
}
