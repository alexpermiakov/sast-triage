# sast-triage

**An LLM agent that triages your SAST findings — bounded, read-only, and
fail-closed — with verdicts cached in git and reviewed by PR.**

SAST scanners emit findings nobody triages. Most are false positives; small
teams have no security staff and large ones have backlogs. The missing work is
what a junior security analyst does: open the flagged file, trace the input,
check sanitization and reachability, deliver a verdict with evidence.
`sast-triage` automates exactly that — and nothing more.

```
findings.sarif ─► INGEST ─► CACHE ─► TRIAGE (agent) ─► REPORT + CACHE PR + ISSUES
                  parse     skip      bounded LLM       exit code
                  SARIF     known     loop, one per
                            verdicts  new finding
```

Deterministic pipeline, exactly one nondeterministic stage — the LLM gets
judgment, never control:

- **Two tools, both read-only**: `read_file` and `grep_repo`, path-validated
  against the repo root (no traversal, no symlinks out, no writes, no exec).
- **Three-valued verdicts**: `benign | exploitable | uncertain`. `benign`
  requires cited `file:line` evidence that the tool re-verifies; every failure
  mode — budget exhaustion, malformed output, ambiguity — lands on
  `uncertain`. Nothing defaults to safe.
- **Everything is bounded**: iteration cap and token budget per finding, a
  findings cap per run, output caps per tool call.
- **Verdicts are cached in git, keyed to the evidence**: a cache hit requires
  the finding's fingerprint *and* a matching hash over the flagged region plus
  every line the verdict cited. Touch any line a verdict relied on and it
  expires. Suppression is keyed to the evidence, not the finding.

## 60-second demo

The repo ships a tiny intentionally-vulnerable sample app under
`testdata/sampleapp/` with a matching SARIF fixture, so you can watch a full
triage run without installing a scanner. You need Go and an
[Anthropic API key](https://console.anthropic.com):

```bash
git clone https://github.com/alexpermiakov/sast-triage && cd sast-triage
export ANTHROPIC_API_KEY=sk-ant-...

go run ./cmd/sast-triage \
  -sarif testdata/findings.sarif \
  -repo testdata/sampleapp \
  -cache /tmp/demo-cache.json \
  -report /tmp/demo-report.md

cat /tmp/demo-report.md
```

Three findings go in: a SQL injection with a taint trace (the agent reads the
handler and confirms it), a hardcoded credential (decided in a single call
from the snippet — no tools needed), and a finding inside `_test.go`
(short-circuited to `benign` by pure rule, zero LLM calls). Run it twice —
the second run is all cache hits and costs zero tokens.

Real output from that exact run (~5,800 tokens total):

> # SAST triage report
>
> 3 findings — **1 benign** (proposed suppressions), **2 exploitable**, **0
> uncertain**. 0 from cache, 3 newly triaged (5766 tokens).
>
> ## Exploitable
>
> ### `app/handlers.go:17` — `go.lang.security.audit.database.string-formatted-query`
>
> - Severity: 8.6 (error) · verdict source: new
> - Reason: The handler reads `id` directly from the HTTP request query
>   parameters (`r.URL.Query().Get("id")`) with no validation or escaping,
>   formats it directly into a SQL query string via `fmt.Sprintf`, and passes
>   the fully-formatted string to `s.db.QueryRow(query)` which executes it as
>   raw SQL. There is no parameterized query […] An attacker can supply a
>   malicious `id` value (e.g. `1 OR 1=1` or a UNION-based payload) to alter
>   the query semantics.
> - Evidence: `app/handlers.go:16`, `app/handlers.go:17`, `app/handlers.go:18`

The report is sorted by required human scrutiny: proposed suppressions first
(veto must be a 30-second action), then exploitable, then uncertain.

## Use it on your repository

`sast-triage` doesn't run the scanner. Anything that emits SARIF 2.1.0 with
stable fingerprints works; [opengrep](https://github.com/opengrep/opengrep)
(the LGPL fork of semgrep CE — same rule format and SARIF shape) is what's
tested:

```bash
cd /path/to/your-repo
# rules: clone github.com/opengrep/opengrep-rules and pass the language dirs you need
opengrep scan -f /path/to/opengrep-rules/go --sarif --dataflow-traces --output findings.sarif

sast-triage -sarif findings.sarif -repo . -cache triage-cache.json -report triage-report.md
```

Semgrep's `--sarif --dataflow-traces` output works identically if you'd
rather stay on it.

Install: `go install github.com/alexpermiakov/sast-triage/cmd/sast-triage@latest`

Outputs: `triage-report.md` (read this), `triage-cache.json` (commit this),
GitHub issues for exploitable findings if you pass `-create-issues`.

### Flags

| Flag | Default | Meaning |
| --- | --- | --- |
| `-effort` | `medium` | depth per finding: `small` / `medium` / `large` (see below) |
| `-max-findings-budget` | `50` | breadth per run: findings triaged by LLM; overflow deferred to the next run (0 = unlimited) |
| `-fail-on-new-exploitable` | off | exit 3 if this run *decides* any finding exploitable; cache hits never trip it — the PR gate |
| `-model` | `claude-sonnet-5` | Anthropic model used for triage |
| `-parallel` | `4` | findings triaged concurrently |
| `-create-issues` | off | file GitHub issues for exploitable findings (needs `GITHUB_TOKEN`) |
| `-link-base` | — | e.g. `https://github.com/owner/repo/blob/<sha>` for clickable evidence |

`-effort` scales how deep the agent digs **per finding**; it never removes a
bound, only moves it:

| | read_file lines | grep matches | token budget | iterations |
| --- | --- | --- | --- | --- |
| `small` | 100 | 25 | 30k | 6 |
| `medium` | 200 | 50 | 60k | 10 |
| `large` | 400 | 100 | 120k | 15 |

(`-token-budget` and `-max-iterations` override the preset individually.
Counterintuitively, *smaller* is not always cheaper: the agent re-sends the
conversation each turn, so many small reads can cost more than one big one —
`small` is for small services, `large` for sprawling codebases where taint
paths cross many files.)

## Run it in CI

This repo triages itself: [`triage.yml`](.github/workflows/triage.yml) is
both the live deployment and the template — copy it into your repo, add the
`ANTHROPIC_API_KEY` secret, and enable *Settings → Actions → General → "Allow
GitHub Actions to create and approve pull requests"*.

- **On pull requests**: scan + triage against the verdict cache committed on
  main. The check fails **only if the PR introduces a new exploitable
  finding** — pre-existing backlog never blocks a PR, and cache hits never
  re-bill. The PR job runs with read-only permissions; the report lands in
  the job summary.
- **On push to main**: full run — exploitable findings become GitHub issues
  (deduped through the cache, so never filed twice), and when the verdict
  cache changed, the workflow refreshes **one** review PR carrying the cache
  delta with the report as its body. *PRs approve suppressions; issues own
  vulnerabilities* — approving a suppression is a code review, with the
  evidence one click away.

Conventions worth keeping if you adapt it: everything pinned — actions by
SHA, the scanner binary by sha256, the ruleset by commit (this is a security
tool), default-deny `permissions:` with per-job elevation, a
`concurrency` group so runs can't race on the cache, and no write permissions
of any kind on PR-triggered jobs. To make human approval of triage PRs
mandatory rather than customary, use a GitHub App token and require reviews
via branch protection.

## Cost, and what the first run looks like

The first run on an existing codebase is the expensive one: every finding is
new. It is bounded on two axes — `-max-findings-budget` (default 50 findings
per run, severity-sorted so the scariest go first) and the per-finding token
budget (60k on `medium`, though typical findings resolve in 2–6k). Overflow
findings are *deferred*, reported as such, and picked up by the next run with
a fresh budget — so a large backlog converts over a few runs without any
babysitting, or in one run if you raise the cap.

Every run after that is incremental: verdicts are cache hits until the code
they cite actually changes. In practice LLM cost drops ~99% after bootstrap.

## FAQ

**What stops prompt injection — a comment saying "this is safe"?**
Repo content enters the prompt as evidence, never as instructions, and the
system prompt says so. Prose claims of safety don't meet the evidence bar for
`benign`: the verdict must cite `file:line` refs, which the tool re-verifies
against the actual files. The worst case for a fooled model is a wrong
verdict — and the dangerous direction (false `benign`) demands the most
proof, is PR-reviewed by a human, and auto-expires when any cited line
changes. I didn't make the model reliable; I made the system safe under an
unreliable model.

**Why commit the cache to git?**
Compared to `.semgrepignore`/`nosemgrep`: per-finding granularity,
non-destructive (verdicts, not deletions), carries reason + evidence +
timestamps, and the PR diff is the audit trail. The agent's memory is
version-controlled and human-reviewed.

**Does it only work with opengrep?**
It consumes SARIF 2.1.0, not any one scanner. It expects stable result
fingerprints (`matchBasedId`, emitted by both opengrep and semgrep) and uses
dataflow traces when present. Other scanners' SARIF should adapt in ingest
(`internal/sarif`) — scanner quirks are a parsing problem, not a prompting
problem.

**Can I use OpenAI / Gemini instead of Claude?**
The loop talks to a one-method `Client` interface
([`internal/agent/client.go`](internal/agent/client.go)); the Anthropic SDK
is one implementation of it. A provider swap is one new file.

**Why not let the agent write the fix?**
Scope. Triage is a judgment task with a verifiable output contract; that's
what an LLM can be safely bounded to. Write access would turn a wrong verdict
into a wrong commit.

## Development

```bash
go vet ./...
go test -race ./...
```

`internal/agent` is the only nondeterministic package and is tested against a
fake client replaying scripted tool-use transcripts; everything else is pure
and table-tested against fixtures in `testdata/`. Architecture decisions are
recorded in [docs/DESIGN.md](docs/DESIGN.md).
