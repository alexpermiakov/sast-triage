# DESIGN.md — sast-triage v1

Status: accepted. This document records the v1 design. Scope changes go through
this file first.

## Problem

SAST emits findings nobody triages (majority are false positives; small orgs have
no security team, large orgs have backlogs). SAST speaks file:line, DAST speaks
URLs; the bridge between them has historically been a human, so it mostly doesn't
exist. This tool automates triage — the work a junior security analyst does:
open the flagged file, trace the input, check sanitization/reachability, deliver
a verdict with evidence.

Origin: observed while owning CI security gates across 250+ repos at a major bank.
Built independently afterward as consultancy R&D — no client code or IP involved.

## v1 scope (triage-only — DAST is v1.1)

```
findings.sarif ─► INGEST ─► CACHE ─► TRIAGE (agent) ─► REPORT + CACHE PR + ISSUES
                  parse     skip      bounded LLM       exit code
                  SARIF     known     loop, one per
                            verdicts  new finding
```

Deterministic pipeline; exactly one nondeterministic stage (triage), quarantined
in `internal/agent`. The LLM gets judgment, never control.

Explicitly OUT of v1: OpenAPI scoping, ZAP, per-PR trigger mode, MCP interface,
call-graph tool, org-wide shared cache, Code Scanning SARIF re-upload.
v1.1 = OpenAPI scoping + ZAP as an optional sink (`--openapi` absent → triage-only
mode). v2 candidates: `find_callers` tool via gopls, confidence field, shared cache
backend.

## Stage contracts

### 1. Ingest (`internal/sarif`)

- Input: SARIF 2.1.0 from `semgrep scan --config auto --sarif --dataflow-traces`.
- Extract per result: ruleId, rule description/tags/severity, message, location
  (file, region, snippet), `fingerprints.matchBasedId/v1`, `codeFlows` taint trace
  (source→sink hops with file:line:snippet), level.
- Findings sorted by security-severity desc before triage (budget goes to the
  scary ones first).

### 2. Cache (`internal/cache`)

- File: `triage-cache.json` at repo root, committed to git. Schema:

```json
{
  "version": 1,
  "entries": {
    "<matchBasedId>": {
      "ruleId": "...",
      "file": "...",
      "verdict": "benign|exploitable|uncertain",
      "reason": "mechanical explanation, cites code behavior",
      "evidence": ["path:line", "path:line-line"],
      "codeHash": "sha256:...",
      "model": "...",
      "decidedAt": "RFC3339",
      "tokensUsed": 0,
      "issueRef": 0
    }
  }
}
```

- Hit = fingerprint present AND codeHash matches current code. codeHash covers
  flagged region + every evidence region (a verdict is a fact about the code it
  read, not about the finding).
- Rationale for git over native suppression (.semgrepignore / nosemgrep):
  per-finding granularity, non-destructive (verdicts, not deletions), carries
  reason/evidence/timestamps, PR-reviewable diff = audit trail, branch-scoped.

### 3. Triage (`internal/agent`)

- Per new finding: agent loop. Tools: `read_file` (≤200 numbered lines),
  `grep_repo` (≤50 matches). Read-only, path-validated, repo-rooted.
- First prompt includes: rule background, finding message, flagged snippet, and
  the SARIF codeFlows trace as the starting map ("verify each hop"). The trace
  usually collapses the loop to 1–2 turns; the loop exists because required
  evidence varies per finding and cannot be known upfront.
- Loop bounds: max 10 iterations, per-finding token budget; exhaustion → uncertain.
- Verdict = structured JSON parsed into Go struct; parse failure → one retry →
  uncertain.
- Asymmetric authority (fail-closed): benign requires positive cited evidence.
  Injection posture: repo content is evidence, not instructions; prose claims of
  safety never satisfy the benign bar. Worst case for a fooled model is a wrong
  verdict, and the dangerous direction (false benign) is the hardest to reach and
  auto-expires on evidence drift.
- Findings triaged independently, parallel via errgroup; results merged by a
  single writer.
- Short-circuit tier (no loop, single cheap call or pure rule): findings in
  `_test.go` / testdata, context-free rule types (e.g. hardcoded credential —
  the evidence is the snippet itself).

### 4. Outputs

The binary's contract: reads SARIF + cache; writes report +
updated cache; returns exit code. No hidden state.

- `triage-report.md`: sorted by required human scrutiny — proposed suppressions
  (benign) FIRST with clickable file:line evidence (veto must be a 30-second
  action), then exploitable, then uncertain.
- Cache delta: ALL verdict classes are written (exploitable verdicts are also
  memory — otherwise re-triaged nightly forever).
- Exploitable findings are ADDITIONALLY routed to GitHub Issues (one per finding,
  deduped by fingerprint, `issueRef` stored in cache entry, label
  `security/triage-confirmed`). PRs approve suppressions; issues own vulnerabilities.
- Exit code: nightly mode always 0 unless the tool itself fails. (Blocking
  exit-1 on confirmed CRITICAL belongs to the per-PR mode, post-v1.)

## CI (nightly workflow)

Trigger: `schedule` (02:00 UTC) + `workflow_dispatch` (bootstrap/manual).
Steps: checkout → setup-go + build → semgrep (SARIF+traces) → sast-triage →
upload artifacts (7-day retention, `if: always()`) → if cache changed: bot commits
to branch `triage/nightly-YYYYMMDD` with `[skip ci]`, opens PR with report as body.

- Bot identity (GitHub App / bot account) so branch protection can require human
  approval on triage PRs — approval enforced by mechanism, not policy.
- `concurrency` group prevents cache races between overlapping runs.
- `--max-findings-budget N` caps run cost; overflow findings deferred as uncertain.
- Public-repo posture: fork-PR approval required in repo settings; findings/report
  kept in artifacts, not logs; secrets only via `secrets.ANTHROPIC_API_KEY`
  (unreachable from fork context); default-deny `permissions:` in every workflow.

## Bootstrap (first run)

`workflow_dispatch` on main → one large PR converting the whole untriaged backlog
into evidence-backed verdicts. PR body leads with exploitables, then suppressions.
Human reviews non-benign closely, spot-checks benign, merges once. All subsequent
runs are incremental (cache hits dominate; LLM cost drops ~99%).

## Testing strategy

- Fixtures: real semgrep SARIF output committed under testdata/ (generate via
  `semgrep scan --config auto --sarif --dataflow-traces` on the sample apps).
- Pure packages: table tests, no mocks.
- Agent package: fake client with scripted transcripts (see CLAUDE.md list).
- One intentionally vulnerable sample endpoint lives in the demo apps so the
  public nightly run always has something real to triage (proof-of-life).

## Amendments (2026-07-18)

Scope changes since v1 acceptance, recorded per the header rule:

- **Per-PR trigger mode is IN scope** (was explicitly out of v1; owner
  decision). Flag: `-fail-on-new-exploitable` → exit code 3 when the run
  _decides_ any finding exploitable. Cache hits never trip the gate: the
  committed cache is the baseline, so pre-existing backlog cannot block a PR —
  only what the PR introduces. Nightly-mode exit-0 semantics are unchanged
  when the flag is absent.
- **The demo app (`demo/vulnerable-app`) is removed.** The repo now dogfoods
  itself: `triage.yml` scans this codebase (excluding `testdata/`) on push and
  PR to main. Push-to-main runs file real issues and refresh one review PR
  (`triage/main`) carrying the cache delta; PR runs are read-only-permission
  jobs that gate on new exploitables. Proof-of-life is the `testdata/`
  smoke-test fixture plus a captured report excerpt in the README. The
  "sample endpoint in the demo apps" line in Testing strategy is superseded.
- **Tool output caps are preset-scaled, still hard-bounded.** `-effort
small|medium|large` scales read_file lines (100/200/400), grep matches
  (25/50/100), per-finding token budget (30k/60k/120k), and iteration cap
  (6/10/15). Medium = the original constants and remains the default;
  explicit `-token-budget`/`-max-iterations` override the preset. No preset
  removes a bound. Tool descriptions advertise the active caps.
- **Scanner portability stance:** differences between SAST tools (fingerprint
  schemes, trace formats, severity mapping) are deterministic ingest concerns
  for `internal/sarif` — per-tool adapters are the v2 path. No per-tool
  prompt/skill files; the agent judges code, not scanner output.

## Key one-liners (rationale record)

- "Deterministic pipeline with a bounded, read-only agent loop in the triage
  stage — the LLM gets judgment, not control."
- "Suppression is keyed to the evidence, not the finding."
- "The agent's memory is version-controlled and PR-reviewable."
- "I didn't make the model reliable; I made the system safe under an unreliable
  model."
- "PRs approve suppressions; issues own vulnerabilities."
- "DAST is an optional consumer of the verdicts, not the point of them."

