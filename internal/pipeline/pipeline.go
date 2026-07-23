// Package pipeline wires the deterministic stages around the one
// nondeterministic one: ingest → cache → triage → report + cache delta +
// issues. The binary's whole contract lives here: read SARIF + cache, write
// report + updated cache, no hidden state.
package pipeline

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/alexpermiakov/sast-triage/internal/agent"
	"github.com/alexpermiakov/sast-triage/internal/cache"
	"github.com/alexpermiakov/sast-triage/internal/github"
	"github.com/alexpermiakov/sast-triage/internal/report"
	"github.com/alexpermiakov/sast-triage/internal/sarif"
	"github.com/alexpermiakov/sast-triage/internal/scope"
)

// IssueCreator routes exploitable verdicts to an issue tracker. ListIssues
// lets filing adopt an already-filed issue instead of duplicating it when a
// cache entry has no issueRef (first filing, or the run that filed it never
// landed on this branch).
type IssueCreator interface {
	CreateIssue(ctx context.Context, title, body string, labels []string) (int, error)
	ListIssues(ctx context.Context, label string) ([]github.Issue, error)
}

// ReviewCommenter posts verdicts inline on a pull request diff — the surface
// people actually read, as opposed to a markdown file in an artifact.
type ReviewCommenter interface {
	CreateReviewComment(ctx context.Context, pr int, path string, line int, commitID, body string) error
	ListReviewComments(ctx context.Context, pr int) ([]github.ReviewComment, error)
}

type Config struct {
	SARIFPath        string
	CachePath        string
	RepoRoot         string
	ReportPath       string
	DigestPath       string // byte-bounded report for size-capped surfaces; empty → skip
	DigestBytes      int    // digest size cap; 0 → report.DefaultDigestBytes
	SummaryPath      string // headline + bounded verdict table, for the seed PR body; empty → skip
	TriagedSARIFPath string // verdict-annotated copy of the input SARIF; empty → skip

	// Scope is what gets triaged, decided by the caller from the trigger
	// event: scope.Full (everything in the SARIF) or scope.Diff (only
	// findings in files changed since BaseRef). Never inferred from cache
	// state. Empty → Full.
	Scope   string
	BaseRef string // required for scope.Diff, e.g. "origin/main"

	Model          string
	MaxIterations  int
	TokenBudget    int // per finding
	MaxFindings    int // run-level cap on LLM-triaged findings; overflow deferred
	MaxReadLines   int // per read_file call; 0 → agent default
	MaxGrepMatches int // per grep_repo call; 0 → agent default
	Parallel       int

	LinkBase string
	RunURL   string // CI run this triage ran in; the summary footer links to it
	// RunLabel names the run in the summary heading, e.g. "seed". The caller
	// derives it from the mode it chose — mode itself stays out of Config, so
	// no pipeline behaviour can ever come to depend on it.
	RunLabel         string
	IssueLabel       string
	IssueTitlePrefix string // prepended to filed issue titles (e.g. "<TEST> ")

	PRNumber  int    // pull request to comment on; 0 → skip inline comments
	CommitSHA string // head SHA the comments anchor to; required with PRNumber

	Client  agent.Client    // nil is allowed when every finding is cached/short-circuit
	Issues  IssueCreator    // nil → skip issue routing
	Reviews ReviewCommenter // nil → skip inline PR comments
	Now     func() time.Time
	Log     io.Writer
}

type Summary struct {
	Total, Benign, Exploitable, Uncertain int
	Cached, Fresh, Deferred               int
	NewExploitable                        int // exploitable verdicts decided this run (not cache hits)
	TokensUsed                            int
	// ToolCalls is the run's total successful read_file/grep_repo calls, over
	// the findings triaged this run. Reported next to the tokens because the
	// two together say what the spend bought: tokens with no tool calls is a
	// model answering from the prompt, or a provider dropping the tools array.
	ToolCalls      int
	IssuesFiled    int
	CommentsPosted int

	// Scoped is how many findings the SARIF held before diff scoping dropped
	// the ones outside the change; equal to Total on a full-scope run.
	Scanned int
	// CacheSeeded reports whether the cache held any entry when the run
	// started. It informs the caller's "this repo has never been seeded"
	// message; it must never change what gets triaged or how.
	CacheSeeded bool
}

type outcome struct {
	finding sarif.Finding
	verdict agent.Verdict
	err     error
}

// Run executes one triage run. It returns an error only when the tool itself
// fails (unreadable input, unwritable output, missing API key while work
// remains); finding-level failures degrade to uncertain verdicts
func Run(ctx context.Context, cfg Config) (Summary, error) {
	if cfg.Parallel <= 0 {
		cfg.Parallel = 4
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Log == nil {
		cfg.Log = io.Discard
	}
	if cfg.IssueLabel == "" {
		cfg.IssueLabel = "security/triage-confirmed"
	}

	findings, err := sarif.ParseFile(cfg.SARIFPath)
	if err != nil {
		return Summary{}, err
	}
	scanned := len(findings)

	// Scope, before the cache is even consulted: triaging a finding outside
	// the change is wasted money on a PR run, and the gate must not fire on
	// code the change never touched.
	if cfg.Scope == scope.Diff {
		changed, err := scope.ChangedFiles(ctx, cfg.RepoRoot, cfg.BaseRef)
		if err != nil {
			return Summary{}, err
		}
		findings = scope.Filter(findings, changed)
		fmt.Fprintf(cfg.Log, "diff scope vs %s: %d changed file(s), %d of %d findings in scope\n",
			cfg.BaseRef, len(changed), len(findings), scanned)
	}

	c, err := cache.Load(cfg.CachePath)
	if err != nil {
		return Summary{}, err
	}
	seeded := len(c.Entries) > 0

	var items []report.Item
	var llmQueue []sarif.Finding

	// Partition: cache hits and pure-rule short circuits cost nothing; only
	// findings that need the LLM count against the run budget. Findings
	// arrive severity-sorted from the parser, so budget goes to the scary
	// ones first.
	for _, f := range findings {
		key := cache.Key{Fingerprint: f.Fingerprint, RuleID: f.RuleID, File: f.File}
		if e, ok := c.Lookup(key, cfg.RepoRoot, agent.FlaggedRegion(f), cfg.Model); ok {
			items = append(items, itemFromEntry(f, e))
			continue
		}
		if v, ok := agent.ShortCircuit(f); ok {
			mergeVerdict(c, cfg, f, v, &items)
			continue
		}
		llmQueue = append(llmQueue, f)
	}

	if cfg.MaxFindings > 0 && len(llmQueue) > cfg.MaxFindings {
		for _, f := range llmQueue[cfg.MaxFindings:] {
			// Deferred, NOT cached: next run gets a fresh budget for these.
			items = append(items, deferredItem(f, cfg.MaxFindings))
		}
		deferred := len(llmQueue) - cfg.MaxFindings
		llmQueue = llmQueue[:cfg.MaxFindings]
		fmt.Fprintf(cfg.Log, "%d findings deferred — re-run to continue (completed verdicts are cached and free) or raise -max-findings-budget\n", deferred)
	}

	if len(llmQueue) > 0 {
		if cfg.Client == nil {
			return Summary{}, fmt.Errorf("%d findings need triage but no LLM client is configured (set ANTHROPIC_API_KEY)", len(llmQueue))
		}
		triager, err := agent.New(cfg.Client, cfg.RepoRoot, agent.Config{
			Model:          cfg.Model,
			MaxIterations:  cfg.MaxIterations,
			TokenBudget:    cfg.TokenBudget,
			MaxReadLines:   cfg.MaxReadLines,
			MaxGrepMatches: cfg.MaxGrepMatches,
		})
		if err != nil {
			return Summary{}, err
		}

		// Findings are triaged independently in parallel; results flow
		// through a channel to this goroutine, the single writer that
		// touches the cache.
		results := make(chan outcome)
		var g errgroup.Group
		g.SetLimit(cfg.Parallel)
		go func() {
			for _, f := range llmQueue {
				g.Go(func() error {
					v, err := triager.TriageFinding(ctx, f)
					results <- outcome{finding: f, verdict: v, err: err}
					return nil
				})
			}
			g.Wait()
			close(results)
		}()

		done := 0
		for o := range results {
			done++
			if o.err != nil {
				// Transport failure: report uncertain but never cache it —
				// a flaky API call is not a fact about the code.
				fmt.Fprintf(cfg.Log, "[%d/%d] triage error for %s: %v\n", done, len(llmQueue), o.finding.Location(), o.err)
				items = append(items, uncachedUncertain(o.finding, fmt.Sprintf("triage failed: %v", o.err)))
				continue
			}
			fmt.Fprintf(cfg.Log, "[%d/%d] %s → %s (%d tokens, %d tool calls)\n", done, len(llmQueue), o.finding.Location(), o.verdict.Verdict, o.verdict.Tokens.Total(), o.verdict.ToolCalls)
			mergeVerdict(c, cfg, o.finding, o.verdict, &items)
		}
	}

	summary := summarize(items)
	summary.Scanned = scanned
	summary.CacheSeeded = seeded

	if cfg.Issues != nil {
		summary.IssuesFiled = fileIssues(ctx, cfg, c, items)
	}
	if cfg.Reviews != nil && cfg.PRNumber > 0 {
		summary.CommentsPosted = postReviewComments(ctx, cfg, items)
	}

	if err := c.Save(cfg.CachePath); err != nil {
		return summary, err
	}
	opts := report.Options{LinkBase: cfg.LinkBase}
	md := report.Render(items, opts)
	if err := os.WriteFile(cfg.ReportPath, []byte(md), 0o644); err != nil {
		return summary, fmt.Errorf("write report: %w", err)
	}
	if cfg.DigestPath != "" {
		digest := report.RenderDigest(items, opts, cfg.DigestBytes)
		if err := os.WriteFile(cfg.DigestPath, []byte(digest), 0o644); err != nil {
			return summary, fmt.Errorf("write digest: %w", err)
		}
	}
	if cfg.SummaryPath != "" {
		sopts := opts
		sopts.Model, sopts.RunURL, sopts.RunLabel = cfg.Model, cfg.RunURL, cfg.RunLabel
		if err := os.WriteFile(cfg.SummaryPath, []byte(report.RenderSummary(items, sopts)), 0o644); err != nil {
			return summary, fmt.Errorf("write summary: %w", err)
		}
	}
	if cfg.TriagedSARIFPath != "" {
		if err := writeTriagedSARIF(cfg, items); err != nil {
			return summary, err
		}
	}
	return summary, nil
}

// writeTriagedSARIF re-emits the input SARIF with this run's verdicts attached
// (properties.triage on every triaged result, a suppression on benign ones) so
// CI can upload post-triage truth to Code Scanning.
func writeTriagedSARIF(cfg Config, items []report.Item) error {
	raw, err := os.ReadFile(cfg.SARIFPath)
	if err != nil {
		return fmt.Errorf("write triaged sarif: %w", err)
	}
	verdicts := make(map[string]sarif.Triage, len(items))
	for _, it := range items {
		verdicts[it.Fingerprint] = sarif.Triage{
			Verdict:  it.Verdict,
			Reason:   it.Reason,
			Evidence: it.Evidence,
			Suppress: it.Verdict == agent.VerdictBenign,
		}
	}
	out, err := sarif.Annotate(raw, verdicts)
	if err != nil {
		return fmt.Errorf("write triaged sarif: %w", err)
	}
	if err := os.WriteFile(cfg.TriagedSARIFPath, out, 0o644); err != nil {
		return fmt.Errorf("write triaged sarif: %w", err)
	}
	return nil
}

// mergeVerdict records one decided verdict in the cache (all verdict classes
// are memory) and appends the report item. A verdict whose evidence cannot be
// hashed is degraded to an uncached uncertain: the cache must never hold an
// entry whose invalidation hash cannot be recomputed.
func mergeVerdict(c *cache.Cache, cfg Config, f sarif.Finding, v agent.Verdict, items *[]report.Item) {
	hash, err := cache.CodeHash(cfg.RepoRoot, agent.FlaggedRegion(f), v.Evidence)
	if err != nil {
		fmt.Fprintf(cfg.Log, "codeHash failed for %s: %v\n", f.Location(), err)
		*items = append(*items, uncachedUncertain(f, fmt.Sprintf("verdict evidence could not be hashed: %v", err)))
		return
	}
	e := cache.Entry{
		RuleID:     f.RuleID,
		File:       f.File,
		Verdict:    v.Verdict,
		Reason:     v.Reason,
		Evidence:   v.Evidence,
		CodeHash:   hash,
		Model:      cfg.Model,
		DecidedAt:  cfg.Now().UTC().Format(time.RFC3339),
		TokensUsed: v.Tokens.Total(),
	}
	if v.ShortCircuit {
		e.Model = "rule:short-circuit"
	}
	// Re-triage must not forget the filed issue — but only an entry about this
	// same finding has an issue to hand over. Identity is checked here for the
	// reason cache.Lookup checks it: a key can be reached by a finding the
	// entry was never about, and inheriting issueRef across that would point
	// one finding's comment thread at another's.
	if prev, ok := c.Entries[f.Fingerprint]; ok && prev.RuleID == f.RuleID && prev.File == f.File {
		e.IssueRef = prev.IssueRef
	}
	c.Entries[f.Fingerprint] = e

	it := itemFromEntry(f, e)
	it.Cached = false
	it.ShortCircuit = v.ShortCircuit
	it.TokensIn, it.TokensOut, it.ToolCalls = v.Tokens.In, v.Tokens.Out, v.ToolCalls
	*items = append(*items, it)
}

// fileIssues routes exploitable verdicts (fresh or cached) to GitHub Issues.
// Dedupe is owned by the cache issueRef; when an entry has none, existing
// issues under the triage label are consulted first — matched by the
// fingerprint marker in the body, then by title — and adopted rather than
// re-filed. This holds even when the run that filed the issue never landed on
// this branch (an unmerged cache review PR). Failures degrade to log lines;
// filing issues must not fail the run or lose the cache delta.
func fileIssues(ctx context.Context, cfg Config, c *cache.Cache, items []report.Item) int {
	filed := 0
	var existing []github.Issue
	listed := false
	for i, it := range items {
		if it.Verdict != agent.VerdictExploitable {
			continue
		}
		e, ok := c.Entries[it.Fingerprint]
		if !ok || e.IssueRef != 0 {
			continue
		}
		if !listed {
			var err error
			if existing, err = cfg.Issues.ListIssues(ctx, cfg.IssueLabel); err != nil {
				// Creating blind risks exactly the duplicate storm this
				// lookup prevents; leave issueRef 0 and let a later run file.
				fmt.Fprintf(cfg.Log, "failed to list existing issues: %v — issue filing skipped this run\n", err)
				return 0
			}
			listed = true
		}

		title := cfg.IssueTitlePrefix + report.IssueTitle(it)
		n := adoptIssue(existing, report.FingerprintMarker(it.Fingerprint), title)
		if n == 0 {
			body := report.IssueBody(it, report.Options{LinkBase: cfg.LinkBase})
			var err error
			if n, err = cfg.Issues.CreateIssue(ctx, title, body, []string{cfg.IssueLabel}); err != nil {
				fmt.Fprintf(cfg.Log, "failed to file issue for %s: %v\n", it.Location(), err)
				continue
			}
			existing = append(existing, github.Issue{Number: n, Title: title, Body: body})
			filed++
		}
		e.IssueRef = n
		c.Entries[it.Fingerprint] = e
		items[i].IssueRef = n
	}
	return filed
}

// postReviewComments puts exploitable verdicts inline on the PR diff, at the
// flagged line, with the reason and cited evidence. This is the surface a
// reviewer actually reads; the markdown report is the archive.
//
// Exploitable only, deliberately. The gate's whole claim is that it does not
// fire on noise, and a bot that also comments on every uncertain finding spends
// that credibility immediately — uncertain findings stay in the report and the
// digest. Dedupe is on the fingerprint marker already present in the body, so
// a re-run on the same PR adds nothing. Every failure degrades to a log line:
// commenting must never fail a run or, worse, mask the gate.
func postReviewComments(ctx context.Context, cfg Config, items []report.Item) int {
	if cfg.CommitSHA == "" {
		fmt.Fprintf(cfg.Log, "inline PR comments skipped: no commit SHA to anchor them to\n")
		return 0
	}
	existing, err := cfg.Reviews.ListReviewComments(ctx, cfg.PRNumber)
	if err != nil {
		// Same reasoning as issue filing: commenting blind risks the duplicate
		// storm the listing prevents.
		fmt.Fprintf(cfg.Log, "failed to list PR review comments: %v — inline comments skipped this run\n", err)
		return 0
	}

	posted := 0
	for _, it := range items {
		if it.Verdict != agent.VerdictExploitable {
			continue
		}
		marker := report.FingerprintMarker(it.Fingerprint)
		if slices.ContainsFunc(existing, func(rc github.ReviewComment) bool {
			return strings.Contains(rc.Body, marker)
		}) {
			continue
		}
		body := report.ReviewCommentBody(it, report.Options{LinkBase: cfg.LinkBase})
		err := cfg.Reviews.CreateReviewComment(ctx, cfg.PRNumber, it.File, it.StartLine, cfg.CommitSHA, body)
		switch {
		case err == nil:
			posted++
		case errors.Is(err, github.ErrLineNotInDiff):
			// Routine: the finding is in a changed file but an unchanged hunk.
			// It is still in the report, the digest, and the gate.
			fmt.Fprintf(cfg.Log, "no inline comment for %s: line is outside the PR diff\n", it.Location())
		default:
			fmt.Fprintf(cfg.Log, "failed to comment on %s: %v\n", it.Location(), err)
		}
	}
	return posted
}

// adoptIssue finds the oldest existing issue for a finding: an exact
// fingerprint-marker match in the body, or failing that the same title (two
// fingerprints can flag the same rule at the same location).
func adoptIssue(existing []github.Issue, marker, title string) int {
	best := 0
	for _, is := range existing {
		if !strings.Contains(is.Body, marker) && is.Title != title {
			continue
		}
		if best == 0 || is.Number < best {
			best = is.Number
		}
	}
	return best
}

func itemFromEntry(f sarif.Finding, e cache.Entry) report.Item {
	return report.Item{
		Fingerprint: f.Fingerprint,
		RuleID:      f.RuleID,
		File:        f.File,
		StartLine:   f.StartLine,
		EndLine:     f.EndLine,
		Severity:    f.Severity,
		Level:       f.Level,
		Message:     f.Message,
		Verdict:     e.Verdict,
		Reason:      e.Reason,
		Evidence:    e.Evidence,
		Cached:      true,
		IssueRef:    e.IssueRef,
	}
}

func uncachedUncertain(f sarif.Finding, reason string) report.Item {
	return report.Item{
		Fingerprint: f.Fingerprint,
		RuleID:      f.RuleID,
		File:        f.File,
		StartLine:   f.StartLine,
		EndLine:     f.EndLine,
		Severity:    f.Severity,
		Level:       f.Level,
		Message:     f.Message,
		Verdict:     agent.VerdictUncertain,
		Reason:      reason,
	}
}

func deferredItem(f sarif.Finding, budget int) report.Item {
	it := uncachedUncertain(f, fmt.Sprintf("deferred: run budget (--max-findings-budget %d) exhausted before this finding", budget))
	it.Deferred = true
	return it
}

func summarize(items []report.Item) Summary {
	s := Summary{Total: len(items)}
	for _, it := range items {
		switch it.Verdict {
		case agent.VerdictBenign:
			s.Benign++
		case agent.VerdictExploitable:
			s.Exploitable++
			if !it.Cached {
				s.NewExploitable++
			}
		default:
			s.Uncertain++
		}
		if it.Cached {
			s.Cached++
		} else {
			s.Fresh++
		}
		if it.Deferred {
			s.Deferred++
		}
		s.TokensUsed += it.TokensIn + it.TokensOut
		s.ToolCalls += it.ToolCalls
	}
	return s
}
