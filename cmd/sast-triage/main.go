// Command sast-triage triages SAST findings with a bounded LLM agent and an
// evidence-keyed suppression cache. This file is flag parsing, wiring, and
// exit codes only; all logic lives in internal/.
//
// Exit codes: 0 success (whatever the verdicts), 1 tool failure, 2 usage
// error, 3 gate tripped (-fail-on-new-exploitable and this run produced new
// exploitable verdicts).
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
		sarifPath        = flag.String("sarif", "findings.sarif", "SARIF 2.1.0 input (opengrep/semgrep --sarif --dataflow-traces)")
		cachePath        = flag.String("cache", "triage-cache.json", "triage cache file (committed to git)")
		repoRoot         = flag.String("repo", ".", "repository root the findings refer to")
		reportPath       = flag.String("report", "triage-report.md", "markdown report output")
		triagedSARIF     = flag.String("triaged-sarif", "", "write a verdict-annotated copy of the input SARIF here (benign findings carry suppressions) for Code Scanning upload; empty = skip")
		model            = flag.String("model", "claude-sonnet-5", "Anthropic model for triage")
		effort           = flag.String("effort", "medium", "triage depth per finding: small|medium|large (scales read/grep caps, token budget, iterations)")
		maxIter          = flag.Int("max-iterations", 10, "agent loop iteration cap per finding (overrides -effort)")
		tokenBudget      = flag.Int("token-budget", 60000, "token budget per finding, input+output (overrides -effort)")
		maxFindings      = flag.Int("max-findings-budget", 50, "max findings triaged by LLM per run; overflow deferred as uncertain (0 = unlimited)")
		parallel         = flag.Int("parallel", 4, "findings triaged concurrently")
		linkBase         = flag.String("link-base", "", "base URL for clickable evidence links, e.g. https://github.com/owner/repo/blob/<sha>")
		createIssues     = flag.Bool("create-issues", false, "file GitHub issues for exploitable findings (needs GITHUB_TOKEN)")
		githubRepo       = flag.String("github-repo", os.Getenv("GITHUB_REPOSITORY"), "owner/name for issue creation")
		issueLabel       = flag.String("issue-label", "security/triage-confirmed", "label for filed issues")
		issueTitlePrefix = flag.String("issue-title-prefix", "", "prefix prepended to filed issue titles, e.g. \"<TEST> \"")
		failOnNewExpl    = flag.Bool("fail-on-new-exploitable", false, "exit 3 if this run decides any finding exploitable (cache hits never trip it) — for PR gating")
	)
	flag.Parse()

	eff, err := pipeline.EffortPreset(*effort)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sast-triage: %v\n", err)
		os.Exit(2)
	}
	// The preset supplies token budget and iteration cap unless the individual
	// flag was set explicitly.
	explicit := map[string]bool{}
	flag.Visit(func(f *flag.Flag) { explicit[f.Name] = true })
	if !explicit["token-budget"] {
		*tokenBudget = eff.TokenBudget
	}
	if !explicit["max-iterations"] {
		*maxIter = eff.MaxIterations
	}

	cfg := pipeline.Config{
		SARIFPath:        *sarifPath,
		CachePath:        *cachePath,
		RepoRoot:         *repoRoot,
		ReportPath:       *reportPath,
		TriagedSARIFPath: *triagedSARIF,
		Model:            *model,
		MaxIterations:    *maxIter,
		TokenBudget:      *tokenBudget,
		MaxFindings:      *maxFindings,
		MaxReadLines:     eff.MaxReadLines,
		MaxGrepMatches:   eff.MaxGrepMatches,
		Parallel:         *parallel,
		LinkBase:         *linkBase,
		IssueLabel:       *issueLabel,
		IssueTitlePrefix: *issueTitlePrefix,
		Log:              os.Stderr,
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
	if *failOnNewExpl && s.NewExploitable > 0 {
		fmt.Fprintf(os.Stderr, "sast-triage: %d new exploitable finding(s) this run — failing the gate\n", s.NewExploitable)
		os.Exit(3)
	}
}
