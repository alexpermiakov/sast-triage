# sast-triage

Automated triage for SAST findings: a bounded, read-only LLM agent does the
work a junior security analyst would — opens the flagged file, traces the
input, checks sanitization and reachability — and delivers a verdict with
cited evidence. Verdicts live in a git-committed, PR-reviewable cache keyed to
the code they were decided on, so each finding is paid for once and re-triaged
only when the relevant code actually changes.

```
findings.sarif ─► INGEST ─► CACHE ─► TRIAGE (agent) ─► REPORT + CACHE PR + ISSUES
                  parse     skip      bounded LLM       exit code
                  SARIF     known     loop, one per
                            verdicts  new finding
```

Deterministic pipeline, exactly one nondeterministic stage — and the LLM gets
judgment, never control.

## How it works

- **Ingest** — parses SARIF 2.1.0 from `semgrep scan --sarif --dataflow-traces`,
  including the taint trace, and sorts findings by security-severity so budget
  goes to the scary ones first.
- **Cache** — `triage-cache.json`, committed to git. A hit requires the
  fingerprint *and* a matching `codeHash` computed over the flagged region plus
  every evidence region the verdict cited. Suppression is keyed to the
  evidence, not the finding: touch any line a verdict relied on and it expires.
- **Triage** — one agent loop per new finding, parallelized. Two tools only,
  both read-only and repo-rooted: `read_file` (≤200 lines) and `grep_repo`
  (≤50 matches). Hard iteration cap, per-finding token budget, run-level
  `-max-findings-budget`. Verdicts are three-valued:
  - `benign` — requires cited `file:line` evidence; unverifiable evidence
    downgrades to uncertain. Never the default.
  - `exploitable` — also routed to GitHub Issues (deduped via the cache).
  - `uncertain` — every failure mode lands here: budget exhaustion, malformed
    verdicts, ambiguity. Fail-closed.
- **Report** — `triage-report.md` sorted by required human scrutiny: proposed
  suppressions first with clickable evidence (veto is a 30-second action),
  then exploitable, then uncertain. PRs approve suppressions; issues own
  vulnerabilities.

Prompt-injection posture: repo content is evidence, never instructions. A
comment claiming code is safe does not meet the evidence bar for `benign`.
The worst case for a fooled model is a wrong verdict — and the dangerous
direction (false benign) demands the most proof and auto-expires on any
evidence drift.

## Install

```bash
go install github.com/alexpermiakov/sast-triage/cmd/sast-triage@latest
# or, from a checkout:
go build -o sast-triage ./cmd/sast-triage
```

You also need [semgrep](https://semgrep.dev) to produce the findings:
`brew install semgrep` or `pipx install semgrep`.

## Run locally

You need an Anthropic API key: create one in the
[Anthropic Console](https://console.anthropic.com) under **API Keys**
(requires an account with billing enabled). Put it in a gitignored `.env`:

```bash
# .env
ANTHROPIC_API_KEY=sk-ant-...
```

### Smoke test with the bundled sample app

The repo ships a tiny intentionally-vulnerable app under `testdata/sampleapp/`
and a matching SARIF fixture, so you can watch a full triage run without
installing semgrep — only the API key is needed:

```bash
set -a; source .env; set +a

go run ./cmd/sast-triage \
  -sarif testdata/findings.sarif \
  -repo testdata/sampleapp \
  -cache /tmp/demo-cache.json \
  -report /tmp/demo-report.md

cat /tmp/demo-report.md
```

Three findings go in: a SQL injection with a taint trace (the agent reads the
handler and should confirm it **exploitable**), a hardcoded password (decided
in a single call from the snippet), and a finding inside `_test.go`
(short-circuited to **benign** by pure rule, no LLM call). Run it twice — the
second run is all cache hits and costs zero tokens.

### Triage a real repository

`sast-triage` does not run the scanner itself — semgrep produces
`findings.sarif`, and `-repo` must point at the same root semgrep scanned so
file paths line up:

```bash
cd /path/to/target-repo

semgrep scan --config auto --sarif --dataflow-traces --output findings.sarif

set -a; source /path/to/.env; set +a
sast-triage -sarif findings.sarif -repo . -cache triage-cache.json -report triage-report.md
```

Outputs: `triage-report.md` (read this), `triage-cache.json` (commit this),
GitHub issues if you pass `-create-issues` with `GITHUB_TOKEN` set. Exit code
is 0 unless the tool itself fails.

Useful flags (`sast-triage -h` for all):

| Flag | Default | Meaning |
| --- | --- | --- |
| `-model` | `claude-sonnet-5` | Anthropic model used for triage |
| `-max-iterations` | `10` | agent loop cap per finding |
| `-token-budget` | `60000` | token budget per finding |
| `-max-findings-budget` | `50` | LLM-triaged findings per run; overflow deferred as uncertain |
| `-parallel` | `4` | findings triaged concurrently |
| `-link-base` | — | e.g. `https://github.com/owner/repo/blob/<sha>` for clickable evidence |
| `-create-issues` | off | file GitHub issues for exploitable findings |

The first run on an existing codebase converts the whole backlog into
evidence-backed verdicts — review that PR once, closely. Every run after is
incremental: cache hits dominate and LLM cost drops ~99%.

## Triaging your own repository

This repo runs a single [`triage` workflow](.github/workflows/triage.yml) against the
bundled demo app (see [Proof of life](#proof-of-life-a-self-triaging-demo) below). To
triage your **own** code nightly, adapt the template below — it scans your source
instead of the demo app.

Add the secret first: **Settings → Secrets and variables → Actions → New repository
secret** → `ANTHROPIC_API_KEY` (`GITHUB_TOKEN` is provided automatically), and enable
**Settings → Actions → General → Workflow permissions → "Allow GitHub Actions to
create and approve pull requests"** so the run can open the PR.

```yaml
name: nightly-triage
on:
  schedule:
    - cron: "0 2 * * *"
  workflow_dispatch: {} # first run / manual

concurrency:
  group: nightly-triage
  cancel-in-progress: false

permissions:
  contents: read

jobs:
  triage:
    runs-on: ubuntu-latest
    permissions:
      contents: write
      issues: write
      pull-requests: write
    steps:
      - uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v7.0.0
      - uses: actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e # v7.0.0
        with:
          go-version: stable

      - run: go install github.com/alexpermiakov/sast-triage/cmd/sast-triage@latest
      # semgrep from its official image, pinned by digest (avoids the
      # pipx/pkg_resources breakage on Python 3.12 runners).
      - name: Scan
        run: |
          docker run --rm -v "$PWD:/src" -w /src \
            semgrep/semgrep@sha256:a9ea2d5621c29d815d90c2a3b2f9571da8972ef4ff855c9e4902681730240e35 \
            semgrep scan --config auto --sarif --dataflow-traces --output findings.sarif

      - name: Triage
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
          GITHUB_TOKEN: ${{ github.token }}
        run: |
          sast-triage -sarif findings.sarif -repo . -create-issues \
            -github-repo "${{ github.repository }}" \
            -link-base "https://github.com/${{ github.repository }}/blob/${{ github.sha }}"

      - name: Open cache PR
        env:
          GH_TOKEN: ${{ github.token }}
        run: |
          if [ -z "$(git status --porcelain -- triage-cache.json)" ]; then exit 0; fi
          BRANCH="triage/nightly-$(date -u +%Y%m%d)"
          git config user.name "sast-triage-bot"
          git config user.email "sast-triage-bot@users.noreply.github.com"
          git checkout -B "$BRANCH"
          git add triage-cache.json
          git commit -m "chore(triage): nightly verdict cache update [skip ci]"
          git push -f origin "$BRANCH"
          gh pr create --head "$BRANCH" \
            --title "Nightly SAST triage: $(date -u +%Y-%m-%d)" \
            --body-file triage-report.md
```

Conventions worth keeping: pin actions by SHA (this is a security tool),
default-deny `permissions:` with per-job elevation, and a `concurrency` group
so overlapping runs can't race on the cache. To make human approval of triage
PRs mandatory rather than customary, use a GitHub App token instead of
`github.token` and require reviews via branch protection.

## Proof of life: a self-triaging demo

`demo/vulnerable-app/` is a small, fixed, deliberately vulnerable Go app (**do not
deploy it**), kept in its own Go module so it never touches the main build or tests.
Its `main.go` has a handful of real bugs on purpose — SQL injection (with a taint
trace), command injection, SSRF, and a hardcoded credential — so a triage run always
has something to find.

The [`triage` workflow](.github/workflows/triage.yml) runs it end to end: scan the app
with semgrep, triage the findings with the bounded agent, and publish the report to the
run summary and a build artifact. It's a fixed target, so nothing is generated and
**nothing is committed** — the app is checked in by hand and the workflow only reads it.
Expect the agent to trace the query parameter into the SQL sink and call it
`exploitable`, decide the hardcoded credential from the snippet alone, and cite
`file:line` evidence for each.

The workflow needs the `ANTHROPIC_API_KEY` secret. It scans only `demo/vulnerable-app`;
`testdata/` holds the frozen unit-test fixtures (pinned to test assertions,
auto-short-circuited to benign) and is never scanned.

Preview a run locally:

```bash
semgrep scan --config auto --sarif --dataflow-traces --output demo.sarif demo/vulnerable-app

set -a; source .env; set +a
sast-triage -sarif demo.sarif -repo . -cache /tmp/triage-cache.json -report demo-report.md
cat demo-report.md
```

## Development

```bash
go vet ./...
go test -race ./...
```

`internal/agent` is the only nondeterministic package and is tested against a
fake client replaying scripted tool-use transcripts; everything else is pure
and table-tested against fixtures in `testdata/`. Architecture decisions are
recorded in [docs/DESIGN.md](docs/DESIGN.md).
