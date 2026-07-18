// Package pipeline wires the deterministic stages around the one
// nondeterministic one: ingest → cache → triage → report + cache delta +
// issues. The binary's whole contract lives here: read SARIF + cache, write
// report + updated cache, no hidden state.
package pipeline

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/alexpermiakov/sast-triage/internal/agent"
	"github.com/alexpermiakov/sast-triage/internal/cache"
	"github.com/alexpermiakov/sast-triage/internal/report"
	"github.com/alexpermiakov/sast-triage/internal/sarif"
)

// IssueCreator routes exploitable verdicts to an issue tracker.
type IssueCreator interface {
	CreateIssue(ctx context.Context, title, body string, labels []string) (int, error)
}

type Config struct {
	SARIFPath  string
	CachePath  string
	RepoRoot   string
	ReportPath string

	Model          string
	MaxIterations  int
	TokenBudget    int // per finding
	MaxFindings    int // run-level cap on LLM-triaged findings; overflow deferred
	MaxReadLines   int // per read_file call; 0 → agent default
	MaxGrepMatches int // per grep_repo call; 0 → agent default
	Parallel       int

	LinkBase         string
	IssueLabel       string
	IssueTitlePrefix string // prepended to filed issue titles (e.g. "<TEST> ")

	Client agent.Client // nil is allowed when every finding is cached/short-circuit
	Issues IssueCreator // nil → skip issue routing
	Now    func() time.Time
	Log    io.Writer
}

type Summary struct {
	Total, Benign, Exploitable, Uncertain int
	Cached, Fresh, Deferred               int
	NewExploitable                        int // exploitable verdicts decided this run (not cache hits)
	TokensUsed                            int
	IssuesFiled                           int
}

type outcome struct {
	finding sarif.Finding
	verdict agent.Verdict
	err     error
}

// Run executes one triage run. It returns an error only when the tool itself
// fails (unreadable input, unwritable output, missing API key while work
// remains); finding-level failures degrade to uncertain verdicts.
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
	c, err := cache.Load(cfg.CachePath)
	if err != nil {
		return Summary{}, err
	}

	var items []report.Item
	var llmQueue []sarif.Finding

	// Partition: cache hits and pure-rule short circuits cost nothing; only
	// findings that need the LLM count against the run budget. Findings
	// arrive severity-sorted from the parser, so budget goes to the scary
	// ones first.
	for _, f := range findings {
		if e, ok := c.Lookup(f.Fingerprint, cfg.RepoRoot, agent.FlaggedRegion(f)); ok {
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
			fmt.Fprintf(cfg.Log, "[%d/%d] %s → %s (%d tokens)\n", done, len(llmQueue), o.finding.Location(), o.verdict.Verdict, o.verdict.TokensUsed)
			mergeVerdict(c, cfg, o.finding, o.verdict, &items)
		}
	}

	summary := summarize(items)

	if cfg.Issues != nil {
		summary.IssuesFiled = fileIssues(ctx, cfg, c, items)
	}

	if err := c.Save(cfg.CachePath); err != nil {
		return summary, err
	}
	md := report.Render(items, report.Options{LinkBase: cfg.LinkBase})
	if err := os.WriteFile(cfg.ReportPath, []byte(md), 0o644); err != nil {
		return summary, fmt.Errorf("write report: %w", err)
	}
	return summary, nil
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
		TokensUsed: v.TokensUsed,
	}
	if v.ShortCircuit {
		e.Model = "rule:short-circuit"
	}
	if prev, ok := c.Entries[f.Fingerprint]; ok {
		e.IssueRef = prev.IssueRef // re-triage must not forget the filed issue
	}
	c.Entries[f.Fingerprint] = e

	it := itemFromEntry(f, e)
	it.Cached = false
	it.ShortCircuit = v.ShortCircuit
	it.TokensUsed = v.TokensUsed
	*items = append(*items, it)
}

// fileIssues routes exploitable verdicts (fresh or cached) to GitHub Issues,
// deduped by the issueRef stored in the cache entry. Failures degrade to log
// lines; filing issues must not fail the run or lose the cache delta.
func fileIssues(ctx context.Context, cfg Config, c *cache.Cache, items []report.Item) int {
	filed := 0
	for i, it := range items {
		if it.Verdict != agent.VerdictExploitable {
			continue
		}
		e, ok := c.Entries[it.Fingerprint]
		if !ok || e.IssueRef != 0 {
			continue
		}
		n, err := cfg.Issues.CreateIssue(ctx, cfg.IssueTitlePrefix+report.IssueTitle(it), report.IssueBody(it, report.Options{LinkBase: cfg.LinkBase}), []string{cfg.IssueLabel})
		if err != nil {
			fmt.Fprintf(cfg.Log, "failed to file issue for %s: %v\n", it.Location(), err)
			continue
		}
		e.IssueRef = n
		c.Entries[it.Fingerprint] = e
		items[i].IssueRef = n
		filed++
	}
	return filed
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
		s.TokensUsed += it.TokensUsed
	}
	return s
}
