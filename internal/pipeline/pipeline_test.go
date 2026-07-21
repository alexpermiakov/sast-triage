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
		CachePath:  filepath.Join(dir, ".sast-triage", "cache.json"),
		RepoRoot:   sampleRoot,
		ReportPath: filepath.Join(dir, "triage-report.md"),
		Model:      "test-model",
		Parallel:   1, // deterministic response ordering for the scripted client
		Now:        func() time.Time { return time.Date(2026, 7, 17, 2, 0, 0, 0, time.UTC) },
	}
}

// degenerateSARIF writes a log in which every result carries the same
// scanner fingerprint, which is what semgrep emits for matchBasedId/v1 when it
// runs without a platform login. Locations are real sampleapp code so verdicts
// hash against something.
func degenerateSARIF(t *testing.T, dir string) string {
	t.Helper()
	type loc struct {
		rule, file string
		line       int
	}
	locs := []loc{
		{"go.sqli", "app/handlers.go", 17},
		{"go.tainted-sql", "app/handlers.go", 17}, // second rule, same line
		{"go.secret", "app/config.go", 7},
		{"go.path", "app/db.go", 3},
	}
	var results []string
	for _, l := range locs {
		results = append(results, fmt.Sprintf(`{"ruleId":%q,"message":{"text":"m"},
			"fingerprints":{"matchBasedId/v1":"requires login"},
			"locations":[{"physicalLocation":{"artifactLocation":{"uri":%q},
				"region":{"startLine":%d,"snippet":{"text":"x"}}}}]}`, l.rule, l.file, l.line))
	}
	body := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"semgrep"}},"results":[` +
		strings.Join(results, ",") + `]}]}`

	p := filepath.Join(dir, "degenerate.sarif")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestReportAndCacheCoverTheSameFindings: the report and the cache are two
// renderings of one run, so a finding decided in one has to appear in the
// other. They are built from separate structures — the report from a slice,
// the cache from a map keyed by fingerprint — and a map silently absorbs a
// duplicate key where a slice does not. That is how a scanner emitting one
// fingerprint for every result produced a report of three findings beside a
// cache holding one, with two verdicts overwritten and the survivor reachable
// under the identity of findings it was never about.
//
// The equality asserted here is per-run and one-directional by design: the
// cache accumulates across runs, and a verdict the run declined to commit
// (deferred, transport failure, unhashable evidence) is deliberately reported
// and deliberately not cached. What may never happen is a decided verdict
// going missing, or two findings landing on one entry.
func TestReportAndCacheCoverTheSameFindings(t *testing.T) {
	dir := t.TempDir()
	cfg := baseConfig(t, dir)
	cfg.SARIFPath = degenerateSARIF(t, dir)
	cfg.Client = &fakeClient{responses: []*agent.Response{
		textResp(`{"verdict": "benign", "reason": "r1", "evidence": ["app/handlers.go:16"]}`),
		textResp(`{"verdict": "exploitable", "reason": "r2", "evidence": ["app/handlers.go:17"]}`),
		textResp(`{"verdict": "benign", "reason": "r3", "evidence": ["app/config.go:7"]}`),
		textResp(`{"verdict": "uncertain", "reason": "r4", "evidence": ["app/db.go:3"]}`),
	}}
	cfg.TriagedSARIFPath = filepath.Join(dir, "triaged.sarif")

	s, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if s.Total != 4 {
		t.Fatalf("Total = %d, want 4 findings reported", s.Total)
	}

	c, err := cache.Load(cfg.CachePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Entries) != 4 {
		t.Fatalf("cache entries = %d, want 4 — one per decided finding, none overwritten", len(c.Entries))
	}

	// Same findings, not merely the same count: every entry is reachable under
	// the rule and file it was decided for.
	for fp, e := range c.Entries {
		flagged := cache.Region{File: e.File, Start: 17, End: 17}
		switch e.File {
		case "app/config.go":
			flagged.Start, flagged.End = 7, 7
		case "app/db.go":
			flagged.Start, flagged.End = 3, 3
		}
		k := cache.Key{Fingerprint: fp, RuleID: e.RuleID, File: e.File}
		if _, ok := c.Lookup(k, cfg.RepoRoot, flagged, cfg.Model); !ok && e.Verdict != "uncertain" {
			t.Errorf("entry %s (%s %s) does not verify under its own identity", fp, e.RuleID, e.File)
		}
	}

	// Each scripted verdict carries its own reason, so four distinct reasons is
	// four verdicts that arrived and stayed. A merge shows up here as a
	// duplicate — the survivor's reason sitting on someone else's finding —
	// which a count alone would not catch.
	reasons := map[string]string{}
	for fp, e := range c.Entries {
		if prev, dup := reasons[e.Reason]; dup {
			t.Errorf("reason %q on two entries (%s and %s): a verdict was shared", e.Reason, prev, fp)
		}
		reasons[e.Reason] = fp
	}

	// The two rules flagging one line are the dangerous pair: identical region,
	// so a shared fingerprint would also produce a matching codeHash, and the
	// cache would confirm one rule's verdict for the other instead of missing.
	sameLine := map[string]cache.Entry{}
	for _, e := range c.Entries {
		if e.File == "app/handlers.go" {
			sameLine[e.RuleID] = e
		}
	}
	if len(sameLine) != 2 {
		t.Fatalf("two rules flag app/handlers.go:17, got %d entries: %v", len(sameLine), sameLine)
	}
	if sameLine["go.sqli"].Reason == sameLine["go.tainted-sql"].Reason {
		t.Error("both rules at one location carry one verdict")
	}
}

// TestSecondRunReusesEveryEntry: identity has to survive a round trip, or the
// fix trades a correctness bug for a cache that never hits. Re-running the
// same scan with no client at all must be free — a miss would demand one.
func TestSecondRunReusesEveryEntry(t *testing.T) {
	dir := t.TempDir()
	cfg := baseConfig(t, dir)
	cfg.SARIFPath = degenerateSARIF(t, dir)
	cfg.Client = &fakeClient{responses: []*agent.Response{
		textResp(`{"verdict": "benign", "reason": "r1", "evidence": ["app/handlers.go:16"]}`),
		textResp(`{"verdict": "benign", "reason": "r2", "evidence": ["app/handlers.go:17"]}`),
		textResp(`{"verdict": "benign", "reason": "r3", "evidence": ["app/config.go:7"]}`),
		textResp(`{"verdict": "benign", "reason": "r4", "evidence": ["app/db.go:3"]}`),
	}}
	if _, err := Run(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}

	second := baseConfig(t, dir)
	second.SARIFPath = cfg.SARIFPath
	second.Client = nil // a single miss would fail the run outright
	s, err := Run(context.Background(), second)
	if err != nil {
		t.Fatalf("second run needed the LLM again: %v", err)
	}
	if s.Cached != 4 || s.Fresh != 0 {
		t.Errorf("cache accounting = %+v, want all 4 served from cache", s)
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
		t.Errorf("NewExploitable = %d, want 1 (exploitable verdicts decided this run)", s.NewExploitable)
	}
	if s.Scanned != 3 {
		t.Errorf("Scanned = %d, want 3 (full scope triages every finding in the SARIF)", s.Scanned)
	}
	if s.CacheSeeded {
		t.Error("CacheSeeded on a first run against an empty cache")
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
		t.Errorf("NewExploitable = %d on a fully cached run; nothing was decided this run", s2.NewExploitable)
	}
	if !s2.CacheSeeded {
		t.Error("CacheSeeded false on a run whose cache held every verdict")
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
	if !strings.Contains(string(md), "## Deferred — not triaged this run (1)") {
		t.Errorf("report must mark deferred findings:\n%s", md)
	}
}

// The digest is what CI publishes to size-capped surfaces, so an empty or
// missing one is a silently broken run summary.
func TestRunWritesBoundedDigest(t *testing.T) {
	dir := t.TempDir()
	cfg := baseConfig(t, dir)
	cfg.DigestPath = filepath.Join(dir, "triage-digest.md")
	cfg.DigestBytes = 1200
	cfg.Client = &fakeClient{responses: []*agent.Response{
		textResp(`{"verdict": "exploitable", "reason": "id flows unsanitized to QueryRow", "evidence": ["app/handlers.go:16"]}`),
		textResp(`{"verdict": "benign", "reason": "sample credential in demo code", "evidence": ["app/config.go:7"]}`),
	}}

	if _, err := Run(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}

	digest, err := os.ReadFile(cfg.DigestPath)
	if err != nil {
		t.Fatalf("digest not written: %v", err)
	}
	if len(digest) > cfg.DigestBytes {
		t.Errorf("digest is %d bytes, over the %d cap", len(digest), cfg.DigestBytes)
	}
	if !strings.Contains(string(digest), "## Exploitable") {
		t.Errorf("digest must carry the exploitable finding:\n%s", digest)
	}
	// The full report stays complete regardless of the digest's cap.
	report, err := os.ReadFile(cfg.ReportPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(report), "## Proposed suppressions") {
		t.Errorf("report must stay complete:\n%s", report)
	}
}

// Default: an operator who never names a digest path still gets no digest, so
// the file only appears when asked for (the Action asks for it by default).
func TestRunSkipsDigestWhenUnset(t *testing.T) {
	dir := t.TempDir()
	cfg := baseConfig(t, dir)
	cfg.Client = &fakeClient{responses: []*agent.Response{
		textResp(`{"verdict": "uncertain", "reason": "no conclusion"}`),
		textResp(`{"verdict": "uncertain", "reason": "no conclusion"}`),
	}}
	if _, err := Run(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "triage-digest.md")); !os.IsNotExist(err) {
		t.Error("no DigestPath configured, yet a digest was written")
	}
}

// The seed PR body is this file. It must exist when asked for, carry the
// attribution the pipeline is the only layer that knows (model, run URL, what
// kind of run this was), and stay small — the findings live in full in the
// cache diff that PR is opened to review.
func TestRunWritesSummary(t *testing.T) {
	dir := t.TempDir()
	cfg := baseConfig(t, dir)
	cfg.SummaryPath = filepath.Join(dir, "triage-summary.md")
	cfg.RunURL = "https://github.com/o/r/actions/runs/7"
	cfg.RunLabel = "seed"
	cfg.Client = &fakeClient{responses: []*agent.Response{
		textResp(`{"verdict": "exploitable", "reason": "id flows unsanitized to QueryRow", "evidence": ["app/handlers.go:16"]}`),
		textResp(`{"verdict": "benign", "reason": "sample credential in demo code", "evidence": ["app/config.go:7"]}`),
	}}

	if _, err := Run(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}

	summary, err := os.ReadFile(cfg.SummaryPath)
	if err != nil {
		t.Fatalf("summary not written: %v", err)
	}
	for _, want := range []string{
		"### sast-triage · seed",
		"**1 exploitable**",
		"❌ exploitable",
		cfg.Model,
		cfg.RunURL,
	} {
		if !strings.Contains(string(summary), want) {
			t.Errorf("summary missing %q:\n%s", want, summary)
		}
	}
	// Evidence is the report's job and the cache diff's; a body that carries
	// it grows without bound.
	if strings.Contains(string(summary), "app/handlers.go:16") {
		t.Errorf("summary must not carry evidence lists:\n%s", summary)
	}
}

// The token split the summary footer reports has to survive the trip from the
// agent through the cache merge, not be recomputed or dropped along the way.
func TestRunReportsTokenSplit(t *testing.T) {
	dir := t.TempDir()
	cfg := baseConfig(t, dir)
	cfg.SummaryPath = filepath.Join(dir, "triage-summary.md")
	cfg.Client = &fakeClient{responses: []*agent.Response{
		textResp(`{"verdict": "uncertain", "reason": "no conclusion"}`),
		textResp(`{"verdict": "uncertain", "reason": "no conclusion"}`),
	}}

	s, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}

	// textResp bills 100 in / 50 out per call, two findings, one call each.
	if s.TokensUsed != 300 {
		t.Errorf("TokensUsed = %d, want 300 (both directions, both findings)", s.TokensUsed)
	}
	summary, err := os.ReadFile(cfg.SummaryPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(summary), "200 in / 100 out tokens") {
		t.Errorf("summary must report input and output separately:\n%s", summary)
	}
}

func TestRunSkipsSummaryWhenUnset(t *testing.T) {
	dir := t.TempDir()
	cfg := baseConfig(t, dir)
	cfg.Client = &fakeClient{responses: []*agent.Response{
		textResp(`{"verdict": "uncertain", "reason": "no conclusion"}`),
		textResp(`{"verdict": "uncertain", "reason": "no conclusion"}`),
	}}
	if _, err := Run(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "triage-summary.md")); !os.IsNotExist(err) {
		t.Error("no SummaryPath configured, yet a summary was written")
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
