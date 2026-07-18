# DESIGN.md — sast-triage

Source of truth for architecture decisions. Scope changes go through this file
first; git history is the amendment record.

## Problem

SAST emits findings nobody triages: the majority are false positives, small
orgs have no security team, large orgs have backlogs. This tool automates the
work a junior security analyst does — open the flagged file, trace the input,
check sanitization/reachability, deliver a verdict with evidence.

Origin: observed while owning CI security gates across 250+ repos at a major
bank; built independently afterward as consultancy R&D — no client code or IP
involved.

## Shape

```
findings.sarif ─► INGEST ─► CACHE ─► TRIAGE (agent) ─► REPORT + CACHE PR + ISSUES
                  parse     skip      bounded LLM       exit code
                  SARIF     known     loop, one per
                            verdicts  new finding
```

Deterministic pipeline; exactly one nondeterministic stage (triage),
quarantined in `internal/agent`. The LLM gets judgment, never control.

Deliberately out of scope (future candidates): `find_callers` tool via gopls,
per-scanner ingest adapters, confidence field, MCP interface, org-wide shared
cache backend, Code Scanning SARIF re-upload.

## Stage contracts

### 1. Ingest (`internal/sarif`)

- Input: SARIF 2.1.0 from `opengrep scan -f <pinned rules> --sarif
  --dataflow-traces`. Opengrep is the supported scanner: LGPL-2.1,
  self-contained binary pinned by sha256, rules repo pinned by commit —
  reproducible scans, no registry fetch, no metrics.
- Extract per result: ruleId, rule description/tags/severity, message, location
  (file, region, snippet), `fingerprints.matchBasedId/v1`, `codeFlows` taint
  trace (source→sink hops with file:line:snippet), level. A result without a
  stable fingerprint gets a synthetic one (rule + location).
- Scanner differences (fingerprint schemes, trace formats, severity mapping)
  are deterministic ingest concerns — per-tool adapters live here, never
  per-tool prompts. The agent judges code, not scanner output.
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
- Rationale for git over scanner-native suppression (ignore files, inline
  suppression comments): per-finding granularity, non-destructive (verdicts,
  not deletions), carries reason/evidence/timestamps, PR-reviewable diff =
  audit trail, branch-scoped.

### 3. Triage (`internal/agent`)

- Per new finding: agent loop. Tools: `read_file`, `grep_repo`. Read-only,
  path-validated, repo-rooted.
- All caps scale with `-effort small|medium|large`, never disappear: read_file
  lines 100/200/400, grep matches 25/50/100, token budget 30k/60k/120k,
  iteration cap 6/10/15. Medium is the default; explicit
  `-token-budget`/`-max-iterations` override the preset. Tool descriptions
  advertise the active caps.
- First prompt includes: rule background, finding message, flagged snippet, and
  the SARIF codeFlows trace as the starting map ("verify each hop"). The trace
  usually collapses the loop to 1–2 turns; the loop exists because required
  evidence varies per finding and cannot be known upfront.
- Budget/iteration exhaustion → uncertain. Verdict = structured JSON parsed
  into a Go struct; parse failure → one retry → uncertain.
- Asymmetric authority (fail-closed): benign requires positive cited evidence.
  Injection posture: repo content is evidence, not instructions; prose claims
  of safety never satisfy the benign bar. Worst case for a fooled model is a
  wrong verdict, and the dangerous direction (false benign) is the hardest to
  reach and auto-expires on evidence drift.
- Findings triaged independently, parallel via errgroup; results merged by a
  single writer.
- Short-circuit tier (no loop, single cheap call or pure rule): findings in
  `_test.go` / testdata, context-free rule types (e.g. hardcoded credential —
  the evidence is the snippet itself).

### 4. Outputs

The binary's contract: reads SARIF + cache; writes report + updated cache;
returns exit code. No hidden state.

- `triage-report.md`: sorted by required human scrutiny — proposed suppressions
  (benign) FIRST with clickable file:line evidence (veto must be a 30-second
  action), then exploitable, then uncertain.
- Cache delta: ALL verdict classes are written (exploitable verdicts are also
  memory — otherwise re-triaged forever).
- Exploitable findings are ADDITIONALLY routed to GitHub Issues (one per
  finding, deduped by fingerprint, `issueRef` stored in cache entry, label
  `security/triage-confirmed`). PRs approve suppressions; issues own
  vulnerabilities.
- Exit codes: 0 success; 1 pipeline failure; 2 usage error; 3 only with
  `-fail-on-new-exploitable` when this run _decides_ a finding exploitable.
  Cache hits never trip the gate: the committed cache is the baseline, so
  pre-existing backlog cannot block a PR — only what the PR introduces.

## CI (`.github/workflows/triage.yml`)

The repo dogfoods itself: scan + triage of this codebase (excluding
`testdata/`) on push and PR to main, plus `workflow_dispatch`.

- PR jobs: read-only permissions; triage against the cache committed on main;
  gate via exit 3. Fork PRs can't see the API key and skip triage with a
  notice instead of failing red.
- Push-to-main jobs: file one issue per exploitable; when the cache changed,
  refresh ONE review PR (branch `triage/main`) carrying the cache delta with
  the report as its body.
- Supply chain: actions pinned by SHA, opengrep binary pinned by sha256, rules
  repo pinned by commit. The rules checkout is excluded from the scan and
  deleted before triage (rule corpora carry intentionally vulnerable
  snippets).
- `concurrency` group prevents cache races; cache commits carry `[skip ci]`;
  `-max-findings-budget` caps run cost, overflow deferred to the next run.
- Public-repo posture: findings/report kept in artifacts, not logs; API key
  only via secrets (unreachable from fork context); default-deny
  `permissions:` with per-job elevation.

## Bootstrap (first run)

`workflow_dispatch` on main → one large review PR converting the untriaged
backlog into evidence-backed verdicts. Review non-benign closely, spot-check
benign, merge once. Everything after is incremental — cache hits dominate and
LLM cost drops ~99%. A scanner or ruleset change that shifts fingerprints
re-runs bootstrap.

## Testing

- Fixtures: scanner SARIF committed under `testdata/`, regenerated via
  `opengrep scan -f <rules> --sarif --dataflow-traces` on
  `testdata/sampleapp` — the intentionally vulnerable smoke-test target.
  Fixture line numbers are pinned to unit tests.
- Pure packages: table tests, no mocks.
- `internal/agent`: fake client replaying scripted tool-use transcripts (see
  CLAUDE.md for the required scenarios).

## Rationale one-liners

- "Deterministic pipeline with a bounded, read-only agent loop in the triage
  stage — the LLM gets judgment, not control."
- "Suppression is keyed to the evidence, not the finding."
- "The agent's memory is version-controlled and PR-reviewable."
- "I didn't make the model reliable; I made the system safe under an
  unreliable model."
- "PRs approve suppressions; issues own vulnerabilities."
