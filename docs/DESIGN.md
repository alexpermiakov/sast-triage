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
cache backend.

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
- One file, mixed models. Entries record the deciding `model`, but the cache is
  not partitioned by it (no per-model files/directories): the same finding would
  then appear in N files, fragmenting the PR diff that *is* the audit trail, and
  splitting ownership of `issueRef`. Model strings also make poor filenames —
  against an OpenAI-compatible endpoint the name is whatever the server reports,
  and the same weights answer to different names on different hosts.
- **A model change retires `uncertain` entries only.** `model` is load-bearing
  in `Lookup` for that one class:
  - `uncertain` is a non-answer. Re-deciding it under the new model costs one
    triage and can only improve on nothing, so a swap is a reason to retry.
  - `benign` and `exploitable` survive. The invalidation contract is cited
    evidence + codeHash — a claim about the code, which says nothing about who
    read it. `Lookup` already ignores `decidedAt` for the same reason: a verdict
    does not expire because time passed, and model identity is the same kind of
    metadata. Re-running a decided verdict re-confirms at full price in the good
    case, and lets a weaker model overturn a stronger one's work in the bad one
    — and swap *direction* is not knowable without a model ranking, which would
    encode a claim the tool cannot verify and that goes stale every release.
  - Asymmetry rationale: a false `exploitable` costs an issue a human closes; a
    false `benign` costs a shipped vulnerability plus an audit trail claiming it
    was reviewed. Keeping `exploitable` across a swap is therefore the safe
    direction, and it preserves `issueRef` rather than leaning on the
    label-listing fallback every run.
  - The control on a wrong `benign` is human review of its citations in the PR
    diff, not a second model's opinion. Re-asking with the prior verdict seeded
    would anchor the new model on the old one's conclusion — a confirmation-
    shaped prompt that costs tokens and buys a biased check.
  - Short-circuit entries carry `model: "rule:short-circuit"` and are always
    `benign`, so no model change reaches them.
- Rationale for git over scanner-native suppression (ignore files, inline
  suppression comments): per-finding granularity, non-destructive (verdicts,
  not deletions), carries reason/evidence/timestamps, PR-reviewable diff =
  audit trail, branch-scoped.

### 3. Triage (`internal/agent`)

- Per new finding: agent loop. Tools: `read_file`, `grep_repo`. Read-only,
  path-validated, repo-rooted.
- Provider-agnostic behind a one-method `Client` interface. Two adapters:
  `openai` (any OpenAI-compatible endpoint — Ollama/vLLM/LM Studio/OpenAI, plain
  net/http, no SDK) and `anthropic` (native SDK).
- Endpoint selection is by `-base-url`, not by naming a provider. `-provider`
  defaults to empty and is inferred: a `-base-url` on its own selects `openai`,
  so the common case never types a provider at all; `-provider anthropic` opts
  into the one API that is not OpenAI-shaped. Naming neither is a usage error
  listing both exits — deliberately not a default, because every default here
  would be an endpoint the operator never asked for. That is what preserves the
  invariant: the tool only ever talks to a host you named or an API you asked
  for by name (point it at local Ollama and nothing leaves the machine).
  `-base-url` is honoured on both paths, including `anthropic`, where it
  overrides the SDK endpoint for a gateway or proxy. It is never accepted and
  silently discarded — a named endpoint traded for `api.anthropic.com` without a
  word is precisely the failure this invariant exists to prevent.
- `-provider openai` stays accepted explicitly, so existing invocations and any
  future second native adapter (which would reintroduce a real choice) keep
  working. The loop keys on tool-use
  blocks, not stop reasons, so adapters only map messages/tools/usage.
  Fail-closed verdicts mean a weaker local model yields more `uncertain`, never
  silent `benign`; the deciding model is recorded per cache entry.
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
- With `-create-issues` (off by default — most teams track vulnerabilities
  elsewhere, e.g. Jira; it is also the fallback surface where Code Scanning
  is unavailable): exploitable findings are ADDITIONALLY routed to GitHub
  Issues (one per finding, deduped by fingerprint, `issueRef` stored in cache
  entry, label `security/triage-confirmed`). Dedupe is owned by the cache
  issueRef, but the cache delta travels via a review PR — until it merges, the
  branch's cache has no issueRef. So before filing, existing issues under the
  label (open AND closed, bounded pagination) are consulted and adopted by the
  fingerprint marker in the body, else by deterministic title; if the listing
  fails, filing is skipped for the run rather than risking duplicates. PRs
  approve suppressions; issues own vulnerabilities.
- With `-triaged-sarif <path>`: a verdict-annotated copy of the input SARIF —
  every triaged result gains a `properties.triage` bag (verdict, reason,
  evidence); benign results also gain a SARIF suppression (kind `external`,
  status `accepted`, justification = reason). Pure transform in
  `internal/sarif`: unmatched results and unmodeled fields round-trip
  unchanged.
- Exit codes: 0 success; 1 pipeline failure; 2 usage error; 3 when this run
  _decides_ a finding exploitable. The gate is on by default (the tool's
  headline behavior; forgetting a flag must not silently disable gating);
  runs that may not fail — push-to-main jobs, report-only runs — opt out
  with `-fail-on-new-exploitable=false`. Cache hits never trip the
  gate: the committed cache is the baseline, so pre-existing backlog cannot
  block a PR — only what the PR introduces.

## CI (`.github/workflows/triage.yml`)

The repo dogfoods itself: scan + triage of this codebase (excluding
`testdata/`) on push and PR to main, plus `workflow_dispatch`.

- Triage runs a local model (default: a tiny Ollama model in a service
  container) — no API key, nothing leaves the runner. Cheap on GitHub-hosted
  runners; swap the model or point at a hosted provider to trade cost for
  quality. A tiny model produces more `uncertain` verdicts (never silent
  `benign`), so the gate stays conservative.
- PR jobs: read-only permissions; triage against the cache committed on main;
  gate via exit 3. No secret is involved, so fork PRs are triaged too (they no
  longer skip).
- Push-to-main jobs: file one issue per exploitable (this workflow passes the
  opt-in `-create-issues`); when the cache changed, refresh ONE review PR
  (branch `triage/main`) carrying the cache delta with the report as its body.
- Push-to-main jobs also upload the triaged SARIF to Code Scanning (category
  `sast-triage`) so the Security tab reflects post-triage truth. GitHub
  ignores the SARIF `suppressions` property on upload, so benign alerts are
  then dismissed via the API (`advanced-security/dismiss-alerts`, SHA-pinned).
  PR jobs stay read-only and do not upload.
- Supply chain: actions pinned by SHA, opengrep binary pinned by sha256, rules
  repo pinned by commit. The rules checkout is excluded from the scan and
  deleted before triage (rule corpora carry intentionally vulnerable
  snippets).
- `concurrency` group prevents cache races; cache commits carry `[skip ci]`;
  `-max-findings-budget` caps run cost, overflow deferred to the next run.
- Public-repo posture: findings/report kept in artifacts, not logs; no LLM
  secret in CI at all (local model), so nothing to leak to fork context;
  default-deny `permissions:` with per-job elevation.

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
