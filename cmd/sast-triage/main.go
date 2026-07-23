// Command sast-triage triages SAST findings with a bounded LLM agent and an
// evidence-keyed suppression cache. This file is flag parsing, wiring, and
// exit codes only; all logic lives in internal/.
//
// Two independent axes, both explicit, neither inferred from the other or from
// cache state: -scope decides WHAT is triaged (diff|full), -mode decides
// whether the result can fail the build (enforce|report|baseline).
//
// Exit codes: 0 success (whatever the verdicts), 1 tool failure, 2 usage
// error, 3 gate tripped (-mode enforce and the run found exploitable findings
// in scope).
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
	"github.com/alexpermiakov/sast-triage/internal/report"
	"github.com/alexpermiakov/sast-triage/internal/scope"
)

func main() {
	var (
		sarifPath        = flag.String("sarif-file", "findings.sarif", "SARIF 2.1.0 input (opengrep/semgrep --sarif --dataflow-traces)")
		cachePath        = flag.String("cache", ".sast-triage/cache.json", "triage cache file (committed to git)")
		repoRoot         = flag.String("repo", ".", "repository root the findings refer to")
		reportPath       = flag.String("report", "triage-report.md", "markdown report output (complete; no size cap)")
		digestPath       = flag.String("digest", "triage-digest.md", "byte-bounded digest of the report, for surfaces that cap size — the Actions step summary (1 MiB) and PR/issue bodies (65,536 chars). On by default: a report too large to publish is the common failure, not the rare one. Empty = skip")
		digestBytes      = flag.Int("digest-bytes", report.DefaultDigestBytes, "size cap for -digest; findings past it are dropped by priority (benign first, exploitable last) and counted in the footer")
		summaryPath      = flag.String("summary", "triage-summary.md", "run headline plus one bounded table (15 rows max, no evidence lists) — the seed PR body, which sits above a cache diff that already holds every verdict in full. Empty = skip")
		triagedSARIF     = flag.String("triaged-sarif", "triaged.sarif", "verdict-annotated copy of the input SARIF (benign findings carry suppressions, nothing is deleted) — upload it to Code Scanning or feed it to DefectDojo. On by default; empty = skip")
		scopeMode        = flag.String("scope", scope.Full, "what to triage: full (every finding in the SARIF) or diff (only findings in files changed since -base-ref). Decided by your trigger, never by cache state")
		baseRef          = flag.String("base-ref", "", "base to diff against for -scope diff, e.g. origin/main")
		mode             = flag.String("mode", pipeline.ModeEnforce, "enforce (exit 3 on exploitable findings in scope), report (advisory, never fails), or baseline (triage everything, gate nothing — seeding a fresh cache)")
		prNumber         = flag.Int("pr", 0, "pull request number to post inline review comments on (exploitable findings only); 0 = skip")
		commitSHA        = flag.String("commit", "", "head SHA the inline comments anchor to; required with -pr")
		provider         = flag.String("provider", "", "LLM API shape: anthropic for Claude's native API, openai for anything OpenAI-compatible. Empty (default) infers openai from -base-url")
		baseURL          = flag.String("base-url", "", "API base URL, e.g. http://localhost:11434/v1 for local Ollama. Selects the OpenAI-compatible path on its own; with -provider anthropic it overrides Claude's endpoint. No default: the tool only ever talks to the endpoint you name")
		model            = flag.String("model", "", "model name for the chosen provider — always required (e.g. claude-sonnet-5 for anthropic, qwen2.5-coder:7b for openai/Ollama)")
		effort           = flag.String("effort", "medium", "triage depth per finding: small|medium|large|xlarge (scales read/grep caps, token budget, iterations)")
		maxIter          = flag.Int("max-iterations", 10, "agent loop iteration cap per finding (overrides -effort)")
		tokenBudget      = flag.Int("token-budget", 60000, "token budget per finding, input+output (overrides -effort)")
		maxFindings      = flag.Int("max-findings-budget", 50, "max findings triaged by LLM per run; overflow deferred as uncertain (0 = unlimited)")
		parallel         = flag.Int("parallel", 4, "findings triaged concurrently")
		linkBase         = flag.String("link-base", "", "base URL for clickable evidence links, e.g. https://github.com/owner/repo/blob/<sha>")
		runURL           = flag.String("run-url", "", "URL of the CI run, linked from the -summary footer, e.g. https://github.com/owner/repo/actions/runs/<id>")
		createIssues     = flag.Bool("create-issues", false, "file GitHub issues for exploitable findings (needs GITHUB_TOKEN)")
		githubRepo       = flag.String("github-repo", os.Getenv("GITHUB_REPOSITORY"), "owner/name for issue creation")
		issueLabel       = flag.String("issue-label", "security/triage-confirmed", "label for filed issues")
		issueTitlePrefix = flag.String("issue-title-prefix", "", "prefix prepended to filed issue titles, e.g. \"<TEST> \"")
	)
	flag.Parse()

	if !scope.Valid(*scopeMode) {
		fmt.Fprintf(os.Stderr, "sast-triage: unknown -scope %q (want full or diff)\n", *scopeMode)
		os.Exit(2)
	}
	if *scopeMode == scope.Diff && *baseRef == "" {
		fmt.Fprintln(os.Stderr, "sast-triage: -scope diff requires -base-ref (e.g. -base-ref origin/main)")
		os.Exit(2)
	}
	if !pipeline.ValidMode(*mode) {
		fmt.Fprintf(os.Stderr, "sast-triage: unknown -mode %q (want enforce, report or baseline)\n", *mode)
		os.Exit(2)
	}
	if *prNumber > 0 && *commitSHA == "" {
		fmt.Fprintln(os.Stderr, "sast-triage: -pr requires -commit (the head SHA inline comments anchor to)")
		os.Exit(2)
	}

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
		DigestPath:       *digestPath,
		DigestBytes:      *digestBytes,
		SummaryPath:      *summaryPath,
		TriagedSARIFPath: *triagedSARIF,
		Scope:            *scopeMode,
		BaseRef:          *baseRef,
		PRNumber:         *prNumber,
		CommitSHA:        *commitSHA,
		Model:            *model,
		MaxIterations:    *maxIter,
		TokenBudget:      *tokenBudget,
		MaxFindings:      *maxFindings,
		MaxReadLines:     eff.MaxReadLines,
		MaxGrepMatches:   eff.MaxGrepMatches,
		Parallel:         *parallel,
		LinkBase:         *linkBase,
		RunURL:           *runURL,
		RunLabel:         runLabel(*mode),
		IssueLabel:       *issueLabel,
		IssueTitlePrefix: *issueTitlePrefix,
		Log:              os.Stderr,
	}

	// Provider selection. -base-url names the endpoint and, on its own, selects
	// the OpenAI-compatible path; -provider anthropic opts into Claude's native
	// API. Naming neither is a usage error rather than a default, because every
	// default would be an endpoint the operator never asked for: the tool only
	// talks to a host you named, or an API you asked for by name. A nil Client
	// is fine — the pipeline only errors if a finding actually needs the LLM
	// (cache-only runs don't).
	if cfg.Model == "" {
		fmt.Fprintln(os.Stderr, "sast-triage: -model is required (e.g. -model claude-sonnet-5, or -model qwen2.5-coder:7b for a local Ollama)")
		os.Exit(2)
	}
	selected := *provider
	if selected == "" {
		if *baseURL == "" {
			fmt.Fprintln(os.Stderr, "sast-triage: name an endpoint with -base-url (e.g. http://localhost:11434/v1 for local Ollama), or pick a native API with -provider anthropic")
			os.Exit(2)
		}
		selected = "openai"
	}
	switch selected {
	case "openai":
		if *baseURL == "" {
			fmt.Fprintln(os.Stderr, "sast-triage: -provider openai requires -base-url (e.g. http://localhost:11434/v1 for local Ollama)")
			os.Exit(2)
		}
		cfg.Client = agent.NewOpenAIClient(*baseURL, os.Getenv("OPENAI_API_KEY"), *parallel)
	case "anthropic":
		// baseURL passes through: empty means the SDK default, non-empty a
		// gateway the operator named. Never silently discarded.
		if key := os.Getenv("ANTHROPIC_API_KEY"); key != "" {
			cfg.Client = agent.NewAnthropicClient(key, *baseURL)
		}
	default:
		fmt.Fprintf(os.Stderr, "sast-triage: unknown -provider %q (want openai or anthropic)\n", *provider)
		os.Exit(2)
	}
	if *createIssues {
		token := os.Getenv("GITHUB_TOKEN")
		if token == "" || *githubRepo == "" {
			fmt.Fprintln(os.Stderr, "sast-triage: -create-issues requires GITHUB_TOKEN and -github-repo (or GITHUB_REPOSITORY)")
			os.Exit(2)
		}
		cfg.Issues = github.New(token, *githubRepo)
	}
	if *prNumber > 0 {
		token := os.Getenv("GITHUB_TOKEN")
		if token == "" || *githubRepo == "" {
			fmt.Fprintln(os.Stderr, "sast-triage: -pr requires GITHUB_TOKEN and -github-repo (or GITHUB_REPOSITORY)")
			os.Exit(2)
		}
		cfg.Reviews = github.New(token, *githubRepo)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	s, err := pipeline.Run(ctx, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sast-triage: %v\n", err)
		os.Exit(1)
	}
	scoped := ""
	if *scopeMode == scope.Diff {
		scoped = fmt.Sprintf(" [diff scope vs %s: %d of %d scanned findings]", *baseRef, s.Total, s.Scanned)
	}
	fmt.Printf("triaged %d findings: %d benign, %d exploitable, %d uncertain (%d cached, %d new, %d deferred, %d tokens, %d tool calls, %d issues filed, %d PR comments)%s\n",
		s.Total, s.Benign, s.Exploitable, s.Uncertain, s.Cached, s.Fresh, s.Deferred,
		s.TokensUsed, s.ToolCalls, s.IssuesFiled, s.CommentsPosted, scoped)

	fail, msg := pipeline.Gate(*mode, s)
	if msg != "" {
		fmt.Fprintf(os.Stderr, "sast-triage: %s\n", msg)
	}
	if fail {
		os.Exit(3)
	}
}

// runLabel names the run for the summary heading. Baseline runs are called
// "seeding" everywhere else — in the docs, the workflow, and the PR title the
// summary becomes the body of — so the heading says "seed" rather than making
// the reader translate the flag value.
func runLabel(mode string) string {
	if mode == pipeline.ModeBaseline {
		return "seed"
	}
	return mode
}
