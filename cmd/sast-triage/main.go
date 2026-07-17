// Command sast-triage triages SAST findings with a bounded LLM agent and an
// evidence-keyed suppression cache. This file is flag parsing, wiring, and
// exit codes only; all logic lives in internal/.
//
// Exit codes: 0 success (whatever the verdicts), 1 tool failure, 2 usage error.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/alexpermiakov/sast-triage/internal/agent"
	"github.com/alexpermiakov/sast-triage/internal/github"
	"github.com/alexpermiakov/sast-triage/internal/pipeline"
)

func main() {
	var (
		sarifPath    = flag.String("sarif", "findings.sarif", "SARIF 2.1.0 input (semgrep --sarif --dataflow-traces)")
		cachePath    = flag.String("cache", "triage-cache.json", "triage cache file (committed to git)")
		repoRoot     = flag.String("repo", ".", "repository root the findings refer to")
		reportPath   = flag.String("report", "triage-report.md", "markdown report output")
		model        = flag.String("model", "claude-sonnet-5", "Anthropic model for triage")
		maxIter      = flag.Int("max-iterations", 10, "agent loop iteration cap per finding")
		tokenBudget  = flag.Int("token-budget", 60000, "token budget per finding (input+output)")
		maxFindings  = flag.Int("max-findings-budget", 50, "max findings triaged by LLM per run; overflow deferred as uncertain (0 = unlimited)")
		parallel     = flag.Int("parallel", 4, "findings triaged concurrently")
		linkBase     = flag.String("link-base", "", "base URL for clickable evidence links, e.g. https://github.com/owner/repo/blob/<sha>")
		createIssues = flag.Bool("create-issues", false, "file GitHub issues for exploitable findings (needs GITHUB_TOKEN)")
		githubRepo   = flag.String("github-repo", os.Getenv("GITHUB_REPOSITORY"), "owner/name for issue creation")
		issueLabel   = flag.String("issue-label", "security/triage-confirmed", "label for filed issues")
	)
	flag.Parse()

	cfg := pipeline.Config{
		SARIFPath:     *sarifPath,
		CachePath:     *cachePath,
		RepoRoot:      *repoRoot,
		ReportPath:    *reportPath,
		Model:         *model,
		MaxIterations: *maxIter,
		TokenBudget:   *tokenBudget,
		MaxFindings:   *maxFindings,
		Parallel:      *parallel,
		LinkBase:      *linkBase,
		IssueLabel:    *issueLabel,
		Log:           os.Stderr,
	}

	if key := os.Getenv("ANTHROPIC_API_KEY"); key != "" {
		cfg.Client = agent.NewAnthropicClient(key)
	}
	if *createIssues {
		token := os.Getenv("GITHUB_TOKEN")
		if token == "" || *githubRepo == "" {
			fmt.Fprintln(os.Stderr, "sast-triage: -create-issues requires GITHUB_TOKEN and -github-repo (or GITHUB_REPOSITORY)")
			os.Exit(2)
		}
		cfg.Issues = github.New(token, *githubRepo)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	s, err := pipeline.Run(ctx, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sast-triage: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("triaged %d findings: %d benign, %d exploitable, %d uncertain (%d cached, %d new, %d deferred, %d tokens, %d issues filed)\n",
		s.Total, s.Benign, s.Exploitable, s.Uncertain, s.Cached, s.Fresh, s.Deferred, s.TokensUsed, s.IssuesFiled)
}
