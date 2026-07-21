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
findings.sarif ─► INGEST ─► SCOPE ─► CACHE ─► TRIAGE (agent) ─► OUTPUTS ─► GATE
                  parse     diff or   skip     bounded LLM       report,    mode
                  SARIF     full      known    loop, one per     SARIF,     decides
                                      verdicts new finding       comments   exit code
```

Deterministic pipeline; exactly one nondeterministic stage (triage),
quarantined in `internal/agent`. The LLM gets judgment, never control.

**Scope and gating are two independent axes, both explicit.** Scope
(`-scope diff|full`, `internal/scope`) decides WHAT is triaged; mode
(`-mode enforce|report|baseline`, `internal/pipeline/mode.go`) decides whether
the result can fail the build. Neither is derived from the other, and neither is
derived from cache presence — implicit behaviour is behaviour nobody can debug
at 2am. The caller maps its trigger onto the pair: `pull_request` → diff +
enforce, `schedule`/`push` → full + report, `workflow_dispatch` → full +
baseline.

Diff scope has a known, unfixable hole: a change in `Foo.java` can make a
pre-existing finding in `Bar.java` exploitable, and nothing keyed on changed
files can see it. This is why the full-scope scheduled run is part of the
design rather than an optional extra — the two runs are a pair. Semgrep's
baseline mode has the same hole. Scope matches on the FLAGGED location only,
never on taint-trace hops: matching hops would pull most of a backlog into scope
whenever a shared helper changes.

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
  stable fingerprint gets a synthetic one (rule + location + snippet).
- **Fingerprints are unique per run, guaranteed at ingest.** Identity is not a
  local concern: it keys the cache, the verdict map that annotates the SARIF
  for Code Scanning, issue dedupe and PR-comment dedupe. Two findings sharing
  one is not a lost cache hit, it is one finding's verdict becoming another's —
  and a `benign` crossing over suppresses a finding nobody triaged, in the
  cache and in Code Scanning at once. So the guarantee is made once here and
  every downstream map inherits it rather than restating it.
  - The scanner's own id is preferred where it is one: it is stable under line
    drift in a way nothing derivable from content is.
  - A value carrying whitespace is not an id. Semgrep run without a platform
    login emits the literal `"requires login"` for `matchBasedId/v1` on *every*
    result, which an emptiness check alone accepts. This shipped: a run
    reported three findings and cached one, the survivor reachable under the
    identity of two findings it was never about.
  - A value the run repeats is not an id either, whatever the scanner meant by
    it. It is discarded for every result carrying it, not just the later ones,
    so identity never depends on emission order.
  - Both fall back to the synthetic id. That id keys on location because rule +
    file + snippet did not separate two matches of one rule in one file, and
    repeated flagged text (a config block, a repeated call shape) is ordinary.
    Line drift then costs a re-triage, which is the correctly-priced failure:
    the cache-safety invariant already prices a miss at money, and the
    alternative prices a collision at a suppressed finding.
  - Results identical in rule, location and text take an occurrence suffix.
    Nothing distinguishes them; they still may not merge.
  - Pinned by `TestFingerprintsAreUnique` in `internal/sarif/sarif_test.go`.
    `Annotate` derives identity from the same function `Parse` does, so a
    verdict is looked up under the fingerprint it was filed under.
- Scanner differences (fingerprint schemes, trace formats, severity mapping)
  are deterministic ingest concerns — per-tool adapters live here, never
  per-tool prompts. The agent judges code, not scanner output.
- Findings sorted by security-severity desc before triage (budget goes to the
  scary ones first).

### 2. Cache (`internal/cache`)

- File: `.sast-triage/cache.json`, committed to git. The directory, not a
  root-level file: it leaves room for config and ignore files beside it, gives
  one clean `CODEOWNERS` line (`/.sast-triage/ @org/security`) so suppression
  changes route to a security reviewer, and one clean `paths-ignore:` entry so
  cache commits do not retrigger CI. Schema:

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

- Hit = entry is about this finding AND codeHash matches current code. codeHash
  covers flagged region + every evidence region (a verdict is a fact about the
  code it read, not about the finding).
- **Cache-safety invariant: a missing, damaged, or unverifiable entry causes
  re-triage, never `benign`.** The cache is a hand-editable file in git, so
  `Lookup` re-checks the evidence bar at the trust boundary rather than assuming
  whatever wrote the file was the agent: `benign` with an empty evidence list is
  a miss, an unmodeled verdict string is a miss, an absent or mismatched
  codeHash is a miss, an unreadable evidence region is a miss, and an entry
  whose `ruleId`/`file` disagree with the finding asking for it is a miss. A
  wiped cache costs one full run's tokens and nothing else. Pinned by
  `TestDamagedEntryNeverSuppresses` in `internal/cache/safety_test.go`.
- **`Lookup` takes a `cache.Key` (fingerprint + ruleId + file), not a bare
  fingerprint.** The fingerprint is the map key but is not on its own proof that
  an entry belongs to the finding asking for it: it originates with the scanner,
  and ingest's uniqueness guarantee is not the cache's to assume — the file is
  hand-editable in git, and a merge or an edit can pair a fingerprint with an
  entry that was never about this finding. So it is re-checked where the entry
  is actually trusted, beside the evidence bar and the codeHash. Two rules
  flagging one line is the case that motivates it: identical region, so a shared
  key also produces a *matching* codeHash, and the cache confirms the wrong
  verdict rather than missing. Pinned by
  `TestEntryForAnotherFindingNeverSuppresses`.
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

- `triage-report.md`: complete and uncapped, sorted by required human scrutiny —
  proposed suppressions (benign) FIRST with clickable file:line evidence (veto
  must be a 30-second action), then exploitable, then uncertain. Findings the
  run never reached (deferred) render as a compact index — location, rule,
  severity — not full stanzas: they carry no verdict, and on a large backlog
  they outnumber real verdicts 100:1, burying the analysis in boilerplate.
- `triage-digest.md` (`-digest`, on by default): a byte-bounded rendering of the
  same items for surfaces that cap size — the Actions step summary (1 MiB) and
  PR/issue bodies (65,536 chars). Two deliberate differences from the report:
  section order is INVERTED (exploitable first), because a capped surface must
  lead with what cannot wait while the benign veto workflow lives in the
  uncapped PR diff and report; and overflow is dropped by priority with the
  footer stating what was dropped. Byte-truncating the report instead would cut
  from the tail — keeping the proposed suppressions and discarding the
  exploitable findings. The cap is a guarantee, not an estimate: the trailer and
  worst-case footer are reserved before any finding is written. Rendering this
  belongs in the binary; making each consumer parse the report's markdown to fit
  their surface is the failure this replaces.
- `triage-summary.md` (`-summary`, on by default): the headline alone — counts,
  no findings. It is the seed PR body. That body sits directly above a
  `cache.json` diff carrying every verdict with its reason and cited evidence,
  in the one place a reviewer can actually edit a verdict; a digest there
  restates thousands of stanzas where nobody can act on them, and on a real
  backlog blows the 65,536-character body cap while doing it. The body links out
  to the run summary (digest) and artifacts (full report) instead. Counts come
  from the same `writeHeadline` all three renderings share, so the PR and the
  report can never disagree about what the run found.
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
- `-triaged-sarif` (`triaged.sarif`, ON by default): a verdict-annotated copy of
  the input SARIF — every triaged result gains a `properties.triage` bag
  (verdict, reason, evidence); benign results also gain a SARIF suppression
  (kind `external`, status `accepted`, justification = reason). Findings are
  RELABELLED, never deleted, so the file stays a complete record of the scan.
  On by default because it is free on every repo and it is the integration
  surface for anything downstream (DefectDojo, Code Scanning); uploading it to
  the Security tab stays an explicit extra step, since private repos need GHAS.
  Pure transform in `internal/sarif`: unmatched results and unmodeled fields
  round-trip unchanged.
- With `-pr <n> -commit <sha>`: exploitable verdicts are posted as inline
  review comments on the PR diff — verdict, reason, cited evidence, on the
  flagged line. This is the product's primary UX; the markdown report is the
  archive. Exploitable ONLY: commenting on uncertain findings too would spend
  the gate's "does not fire on noise" credibility immediately. Dedupe is on the
  fingerprint marker in the comment body (not the cache — a comment belongs to
  one PR, the cache outlives every PR). A line outside the diff is a routine
  skip, not a failure, and every comment failure degrades to a log line:
  commenting must never fail a run or mask the gate.
- Exit codes: 0 success; 1 pipeline failure; 2 usage error; 3 gate tripped.
  The gate is `-mode enforce` + at least one `exploitable` finding in scope,
  and `enforce` is the default (forgetting a flag must not silently disable
  gating). Two decisions:
  - **Exploitable only.** Gating on `uncertain` would fire on every budget
    exhaustion and every ambiguity. A gate that fires on noise is a gate that
    gets disabled within a week, and then nothing is gated.
  - **Cached exploitables count.** The rejected alternative — gate only on
    verdicts decided this run — makes the exit code a function of cache state,
    so the same code passes or fails depending on whether a cache update merged
    first, and a wiped cache reclassifies the entire backlog as "new". Scope,
    not cache freshness, is what keeps the backlog from blocking a PR: a
    diff-scoped run only ever sees findings in files the change touched.
  - One exception, and it only ever RELAXES the gate: on a repo whose cache is
    empty, `enforce` reports instead of failing and says to seed first. There is
    no reviewed baseline to enforce against, and a wall of failures on a repo
    that has never been seeded teaches people the tool is broken. It is stated
    on stderr rather than passing silently.

## CI (`.github/workflows/triage-{pr,seed}.yml`)

The repo dogfoods itself: scan + triage of this codebase (excluding
`testdata/`). THREE workflow files, one per trigger, rather than one file with
conditionals on `github.event_name`. Each one's scope, gating, permissions and
cache destination are then readable top to bottom without cross-referencing the
other two — the conditionals were where the surprising behaviour hid.

- Triage runs a local model (default: a tiny Ollama model in a service
  container) — no API key, nothing leaves the runner. Cheap on GitHub-hosted
  runners; swap the model or point at a hosted provider to trade cost for
  quality. A tiny model produces more `uncertain` verdicts (never silent
  `benign`), so the gate stays conservative.
- `triage-pr.yml` (`pull_request`): `scope: diff` + `mode: enforce` +
  `cache-write: branch` + inline comments. Checks out the PR HEAD SHA (not the
  merge commit) so the cache commit fast-forwards the head branch, with
  `fetch-depth: 0` for the base ref.
- A scheduled full-scope run (`scope: full` + `mode: report` +
  `cache-write: none`, filing issues and uploading the triaged SARIF to Code
  Scanning) is what closes diff scope's cross-file hole, and the README
  documents it as step 3 of the recommended setup. **It is currently not
  dogfooded in this repo** — there is no scheduled workflow here, so this
  codebase is covered by PR-scoped triage only. Adding one back is the fix if
  that gap matters; until then the docs describe a practice the repo does not
  follow, which is worth knowing before citing it as evidence.
- `triage-seed.yml` (`workflow_dispatch`): `scope: full` + `mode: baseline` +
  `cache-write: pr`. See Bootstrap below.
- **The cache is never bot-PR'd onto a protected branch.** PR runs commit the
  delta to the PR's own head branch, so it reaches main through the merge a
  human was already reviewing; `cache-write: pr` exists only for seeding, where
  there is no branch of one's own. Pushes use `GITHUB_TOKEN` deliberately —
  pushes made with it do not retrigger workflows, so a cache commit cannot start
  the run that writes the next cache commit.
- Fork PRs get a read-only token and no secrets. Both degrade rather than
  crash: no API key → triage skipped with a notice (a contributor cannot fix a
  missing secret, and a red X they cannot act on trains everyone to ignore the
  check); read-only token → the cache delta ships in the artifact instead, with
  triage and the gate unaffected.
- The gate is re-raised at the END of the composite action, after outputs are
  written and the cache is committed. Exit 3 is captured, not propagated
  immediately: those verdicts were paid for, and a failing check with no report
  attached is a check people learn to ignore.
- Supply chain: actions pinned by SHA, opengrep binary pinned by sha256, rules
  repo pinned by commit. The rules checkout is excluded from the scan and
  deleted before triage (rule corpora carry intentionally vulnerable
  snippets).
- `concurrency` group prevents cache races; cache commits carry `[skip ci]`;
  `-max-findings-budget` caps run cost, overflow deferred to the next run.
- Public-repo posture: findings/report kept in artifacts, not logs; no LLM
  secret in CI at all (local model), so nothing to leak to fork context;
  default-deny `permissions:` with per-job elevation.

## Bootstrap (seeding)

Seeding is a deliberate one-off a maintainer triggers, not something that
happens implicitly on whichever run reaches an empty cache first.
`workflow_dispatch` → `scope: full` + `mode: baseline` + `cache-write: pr` →
ONE pull request titled "seed sast-triage cache", converting the untriaged
backlog into evidence-backed verdicts.

**That PR is the security review, and it is the most valuable artifact this tool
produces**: the entire proposed suppression set, each entry carrying its
reasoning and the `file:line` evidence behind it, reviewed once by a human who
can accept, edit, or delete any of it. Review non-benign closely, spot-check
benign, merge once. Everything after is incremental — a feature PR adds 0–3
cache lines and stays invisible; cache hits dominate and LLM cost drops ~99%.

A scanner or ruleset change that shifts fingerprints wholesale means re-seeding.
A PR that arrives at an unseeded repo does not seed it as a side effect: it runs
advisory-only, does not gate, and says to seed first.

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
- "Scope and gating are separate explicit inputs; nothing is inferred from
  cache state."
- "The gate people don't disable, because it doesn't fire on noise."
- "A wiped cache costs money, never safety."
- "The cache arrives on main through your merge, never a bot's PR."
