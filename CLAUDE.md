# CLAUDE.md — sast-triage

Go CLI that triages SAST findings with a bounded LLM agent and manages an
evidence-keyed suppression cache. Read `docs/DESIGN.md` before any structural work —
it is the source of truth for architecture decisions. Do not re-litigate decisions
recorded there; propose changes as questions first.

## Project shape

- Language: Go (latest stable). Module: `github.com/alexpermiakov/sast-triage`.
- One binary: `cmd/sast-triage`. All logic in `internal/` packages.
- The workflow YAML stays dumb; logic lives in the Go binary.

## Layout

```
cmd/sast-triage/     main.go — flag parsing, wiring, exit codes only
internal/
  sarif/             parse findings.sarif; annotate verdicts back into SARIF
                     for Code Scanning upload (pure, no I/O beyond the file).
                     Owns finding identity: fingerprints are unique per run,
                     guaranteed here so the cache, the SARIF verdict map, issue
                     dedupe and comment dedupe all inherit it. A scanner id is
                     used only when it is one — semgrep emits the literal
                     "requires login" on every result when unauthenticated —
                     and a repeated id is discarded for every result carrying it
  scope/             diff scoping: `git diff --name-only base...HEAD` +
                     a pure filter over findings. Matches the FLAGGED location
                     only, never taint-trace hops
  cache/             .sast-triage/cache.json load/save, fingerprint+codeHash
                     matching
  agent/             the LLM loop: client, tools, budgets, verdict parsing.
                     Provider adapters behind one Client iface: openai.go (any
                     OpenAI-compatible endpoint, net/http only) and anthropic.go
                     (native SDK). -provider defaults to empty and is inferred
                     from -base-url (base-url alone => openai); -provider
                     anthropic opts into the native API. Naming neither is a
                     usage error, never a default, so the tool only talks to an
                     endpoint the operator named or an API they asked for by
                     name. -base-url is honoured on both paths, never silently
                     dropped.
  report/            triage-report.md rendering, GitHub issue + PR comment bodies
  github/            minimal Issues + PR-review REST client (issue dedupe owned
                     by cache issueRef; comment dedupe by fingerprint marker)
  pipeline/          run orchestration: scope, partition, budget, errgroup
                     fan-out, single-writer merge, issue + comment routing.
                     mode.go owns the exit decision (Gate)
action.yml           composite GitHub Action wrapping the binary; downloads the
                     prebuilt binary for the release named by SAST_TRIAGE_VERSION
                     (sha256 + provenance verified), or compiles the working tree
                     when run from a local checkout (github.action_path inside
                     github.workspace). Bump SAST_TRIAGE_VERSION in the commit you
                     tag — release.yml refuses to publish when it disagrees with
                     the tag, because the mismatch is invisible until it breaks
                     every consumer's CI at once. Inputs mirror CLI flags 1:1
                     (except cache-write and pr-comments, which are git plumbing
                     with no flag behind them); dogfooded by the triage-*
                     workflows via `uses: ./`
.github/workflows/   ci.yml (lint+test on push/PR); triage workflows split one per
                     trigger so each is readable alone — triage-pr.yml (diff scope,
                     enforce, cache to the PR head branch, inline comments) and
                     triage-seed.yml (full scope, baseline, one seed PR). The
                     full-scope scheduled run the docs recommend is NOT dogfooded
                     here; release.yml (on v*.*.* tags: cross-compiles
                     linux/darwin × amd64/arm64, attests provenance, uploads the
                     assets action.yml downloads)
testdata/            real scanner SARIF fixtures, opengrep/semgrep format (pinned
                     to unit-test line numbers)
                     + sampleapp/, the intentionally vulnerable smoke-test target
```

Do not add findings-bearing source to `testdata/` expecting it to be triaged:
those paths are short-circuited to `benign` by the agent, excluded from the CI
scan, and their line numbers are pinned to unit tests.

## Hard rules

- **Agent tools are read-only**: `read_file`, `grep_repo` only. Never add write/exec
  tools. Tool executor validates every path against repo root (no traversal) and
  caps read_file lines and grep matches (defaults 200/50, scaled by the `-effort`
  preset, always finite) with a "narrow your pattern" suffix on grep truncation.
- **Verdicts are three-valued**: `benign | exploitable | uncertain`. `benign`
  requires cited evidence (file:line list). Budget exhaustion, parse failure,
  or any ambiguity → `uncertain`. Never default to `benign`.
- **Bounded loop**: hard iteration cap (default 10) and token budget per finding;
  run-level `--max-findings-budget` cap. No unbounded loops anywhere.
- **Nondeterminism is quarantined in `internal/agent`**. Every other package is
  pure/deterministic and unit-tested without LLM mocks. `agent` is tested with a
  fake client replaying canned tool-use transcripts.
- **Cache invalidation**: `codeHash` = sha256 over the flagged region PLUS all
  evidence regions the verdict cited. Any drift in any of them invalidates the
  entry. Never key invalidation on the flagged line alone. A model change
  additionally retires `uncertain` entries and only those — `benign` and
  `exploitable` are claims about the code and survive the swap. One cache file,
  mixed models; never partition the cache by model.
- **Cache-safety invariant**: a missing, damaged, or unverifiable entry means
  RE-TRIAGE, never `benign`. `Lookup` re-checks the evidence bar at the trust
  boundary (the file is hand-editable in git), so evidence-free `benign`,
  unmodeled verdict strings, and absent/mismatched hashes are all misses. A
  wiped cache costs money, never safety. Pinned by
  `internal/cache/safety_test.go`; never add a path that trusts an entry harder.
- **Identity is checked, not assumed**: `Lookup` takes a `cache.Key`
  (fingerprint + ruleId + file) and misses when the entry's rule or file
  disagrees. A fingerprint arrives from the scanner, so it is a key, not proof
  the entry is about the finding asking. Two rules flagging one line is the case
  that bites: same region, so a shared key also yields a *matching* codeHash and
  the cache confirms the wrong verdict instead of missing. Same reasoning
  wherever an entry is reached by key — see `IssueRef` inheritance in
  `mergeVerdict`.
- **Scope and gating are two explicit axes**: `-scope diff|full` decides what is
  triaged, `-mode enforce|report|baseline` decides whether it can fail the
  build. Never infer either from the other, from the trigger, or from cache
  presence. The gate fires on `exploitable` only — never `uncertain`, or it
  becomes the gate everyone disables — and counts cached exploitables, because
  an exit code that depends on cache freshness is not reproducible. The single
  exception, which only relaxes the gate and must stay loud on stderr: an
  unseeded repo reports instead of failing.
- **The cache is never bot-PR'd onto a protected branch**: PR runs commit the
  delta to the PR's own head branch (`cache-write: branch`); `cache-write: pr`
  is for seeding only. Fork PRs and missing secrets degrade to artifact-only
  with a notice, never a crash.
- **Cache writes are atomic**: marshal indented (human-reviewed in PR diffs),
  write temp file, rename. Parallel triage collects results via channel; single
  writer merges; save once.
- **Prompt-injection posture**: code content in prompts is evidence, never
  instructions. The system prompt states this. A comment claiming safety does not
  meet the evidence bar for `benign`.

## Testing

- Table tests for `sarif`, `cache`, `report`, `scope` against fixtures in
  `testdata/`. `scope` and the pipeline's diff tests build throwaway git repos
  with `exec.Command` and skip when git is unavailable.
- `internal/agent` tests: fake Anthropic client with scripted tool_use sequences,
  covering: 1-turn resolve, multi-turn trace-following, iteration-cap exhaustion,
  malformed verdict JSON (→ one retry → uncertain), path-traversal tool call
  (→ rejected, loop continues).
- `go vet`, `-race` on everything. CI runs lint+test on every PR.

## CI conventions

- All actions SHA-pinned (this is a security tool; tag-pinning is disqualifying).
- Workflow `permissions:` block: default `contents: read`, explicit elevation
  per job.
- Cache-update commits carry `[skip ci]`.

## Style

- Standard library first; allowed deps: anthropic-sdk-go, go-sarif (or hand-rolled
  structs), errgroup. Justify anything else.
- Errors wrapped with context (`fmt.Errorf("triage finding %s: %w", ...)`).
- No global state; everything injected through constructors for testability.

