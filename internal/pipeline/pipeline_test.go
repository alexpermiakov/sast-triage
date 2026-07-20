package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alexpermiakov/sast-triage/internal/agent"
	"github.com/alexpermiakov/sast-triage/internal/cache"
	"github.com/alexpermiakov/sast-triage/internal/github"
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
	titles   []string
	bodies   []string
	existing []github.Issue
	listErr  error
}

func (f *fakeIssues) CreateIssue(_ context.Context, title, body string, _ []string) (int, error) {
	f.titles = append(f.titles, title)
	f.bodies = append(f.bodies, body)
	return 76 + len(f.titles), nil
}

func (f *fakeIssues) ListIssues(_ context.Context, _ string) ([]github.Issue, error) {
	return f.existing, f.listErr
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
	cfg.TriagedSARIFPath = filepath.Join(dir, "triaged.sarif")

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

	// Triaged SARIF: all three verdicts attached, only the two benign
	// findings suppressed. Field-level shape is covered in internal/sarif.
	var triaged struct {
		Runs []struct {
			Results []struct {
				Properties   struct{ Triage map[string]any }
				Suppressions []any
			}
		}
	}
	raw, err := os.ReadFile(cfg.TriagedSARIFPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &triaged); err != nil {
		t.Fatal(err)
	}
	bags, suppressed := 0, 0
	for _, res := range triaged.Runs[0].Results {
		if res.Properties.Triage != nil {
			bags++
		}
		if len(res.Suppressions) > 0 {
			suppressed++
		}
	}
	if bags != 3 || suppressed != 2 {
		t.Errorf("triaged sarif: %d triage bags (want 3), %d suppressed (want 2)", bags, suppressed)
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

// TestRunAdoptsExistingIssueWhenCacheLostRef replays the duplicate-issue
// incident: a run files an issue, but its cache delta (carrying the issueRef)
// never lands on the branch — the review PR is unmerged. The next run
// re-triages from scratch and must adopt the existing issue, not file a copy.
func TestRunAdoptsExistingIssueWhenCacheLostRef(t *testing.T) {
	sqliVerdict := `{"verdict": "exploitable", "reason": "id flows unsanitized to QueryRow", "evidence": ["app/handlers.go:16", "app/handlers.go:17-18"]}`
	secretVerdict := `{"verdict": "benign", "reason": "sample credential in demo code", "evidence": ["app/config.go:7"]}`

	first := baseConfig(t, t.TempDir())
	first.Client = &fakeClient{responses: []*agent.Response{textResp(sqliVerdict), textResp(secretVerdict)}}
	firstIssues := &fakeIssues{}
	first.Issues = firstIssues
	if _, err := Run(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	if len(firstIssues.titles) != 1 {
		t.Fatalf("first run filed %d issues, want 1", len(firstIssues.titles))
	}

	// Second run: fresh cache dir (the delta never merged), but the issue
	// exists on GitHub. Adopt #77 via the fingerprint marker in its body.
	second := baseConfig(t, t.TempDir())
	second.Client = &fakeClient{responses: []*agent.Response{textResp(sqliVerdict), textResp(secretVerdict)}}
	secondIssues := &fakeIssues{existing: []github.Issue{
		{Number: 77, Title: firstIssues.titles[0], Body: firstIssues.bodies[0]},
	}}
	second.Issues = secondIssues

	s, err := Run(context.Background(), second)
	if err != nil {
		t.Fatal(err)
	}
	if len(secondIssues.titles) != 0 || s.IssuesFiled != 0 {
		t.Errorf("duplicate filed: created %v, summary %+v", secondIssues.titles, s)
	}
	c, _ := cache.Load(second.CachePath)
	sqli := c.Entries["0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9_0"]
	if sqli.IssueRef != 77 {
		t.Errorf("issueRef = %d, want the adopted issue 77", sqli.IssueRef)
	}
}

// TestRunSkipsFilingWhenListFails: creating blind risks the duplicate storm
// the lookup prevents, so a failed list defers filing to a later run.
func TestRunSkipsFilingWhenListFails(t *testing.T) {
	cfg := baseConfig(t, t.TempDir())
	cfg.Client = &fakeClient{responses: []*agent.Response{
		textResp(`{"verdict": "exploitable", "reason": "unsanitized flow", "evidence": ["app/handlers.go:16"]}`),
		textResp(`{"verdict": "benign", "reason": "sample credential", "evidence": ["app/config.go:7"]}`),
	}}
	issues := &fakeIssues{listErr: fmt.Errorf("api down")}
	cfg.Issues = issues

	s, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(issues.titles) != 0 || s.IssuesFiled != 0 {
		t.Errorf("filed despite failed list: %v", issues.titles)
	}
	c, _ := cache.Load(cfg.CachePath)
	sqli := c.Entries["0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9_0"]
	if sqli.IssueRef != 0 {
		t.Errorf("issueRef = %d, want 0 so a later run retries filing", sqli.IssueRef)
	}
}

func TestAdoptIssue(t *testing.T) {
	marker := "<!-- sast-triage:fingerprint:abc_0 -->"
	title := "[sast-triage] tainted-sql-string at app/handlers.go:17"
	existing := []github.Issue{
		{Number: 90, Title: "unrelated", Body: "hand-filed"},
		{Number: 78, Title: "renamed by a human", Body: "details\n" + marker + "\n"},
		{Number: 74, Title: title, Body: "no marker, filed before markers existed"},
	}
	tests := map[string]struct {
		marker, title string
		want          int
	}{
		"marker match survives retitling": {marker, "some new title", 78},
		"title match without marker":      {"<!-- sast-triage:fingerprint:zzz_0 -->", title, 74},
		"both match: oldest wins":         {marker, title, 74},
		"no match":                        {"<!-- sast-triage:fingerprint:zzz_0 -->", "nope", 0},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if got := adoptIssue(existing, tc.marker, tc.title); got != tc.want {
				t.Errorf("adoptIssue = %d, want %d", got, tc.want)
			}
		})
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

// Switching models re-triages uncertain entries and nothing else: a
// non-answer is worth re-deciding under a new model, a decided verdict is a
// claim about the code that survives the swap.
func TestRunModelChangeRetriagesOnlyUncertain(t *testing.T) {
	dir := t.TempDir()

	cfg := baseConfig(t, dir)
	cfg.Model = "model-a"
	cfg.Client = &fakeClient{responses: []*agent.Response{
		textResp(`{"verdict": "uncertain", "reason": "could not follow the query into the driver"}`),
		textResp(`{"verdict": "benign", "reason": "sample credential in demo code, not a live secret", "evidence": ["app/config.go:7"]}`),
	}}
	s, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if s.Uncertain != 1 || s.Benign != 2 {
		t.Fatalf("first run summary = %+v, want 1 uncertain + 2 benign", s)
	}

	// Same findings, different model. Only the uncertain one may reach the LLM;
	// a second scripted response is deliberately absent, so any extra call
	// exhausts the script and surfaces as an uncertain verdict.
	cfg2 := baseConfig(t, dir)
	cfg2.Model = "model-b"
	client2 := &fakeClient{responses: []*agent.Response{
		textResp(`{"verdict": "exploitable", "reason": "id flows unsanitized to QueryRow", "evidence": ["app/handlers.go:16", "app/handlers.go:17-18"]}`),
	}}
	cfg2.Client = client2
	s2, err := Run(context.Background(), cfg2)
	if err != nil {
		t.Fatal(err)
	}
	if client2.calls != 1 {
		t.Errorf("LLM calls on model change = %d, want 1 (only the uncertain finding re-triages)", client2.calls)
	}
	if s2.Cached != 2 || s2.Fresh != 1 {
		t.Errorf("model change accounting = %+v, want 2 cached + 1 fresh", s2)
	}
	if s2.Exploitable != 1 || s2.Benign != 2 {
		t.Errorf("model change summary = %+v", s2)
	}

	c, err := cache.Load(cfg2.CachePath)
	if err != nil {
		t.Fatal(err)
	}
	sqli := c.Entries["0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9_0"]
	if sqli.Verdict != "exploitable" || sqli.Model != "model-b" {
		t.Errorf("re-triaged entry = %+v, want exploitable decided by model-b", sqli)
	}

	// Third run, model unchanged: a stable model re-runs nothing, so a nil
	// client is enough.
	cfg3 := baseConfig(t, dir)
	cfg3.Model = "model-b"
	s3, err := Run(context.Background(), cfg3)
	if err != nil {
		t.Fatalf("stable model must need no client: %v", err)
	}
	if s3.Cached != 3 || s3.Fresh != 0 {
		t.Errorf("stable model accounting = %+v, want everything cached", s3)
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
