# Security Policy

## Reporting a vulnerability

Please do not open public issues for suspected vulnerabilities in sast-triage.

Report privately via GitHub's private vulnerability reporting:
<https://github.com/alexpermiakov/sast-triage/security/advisories/new>

You'll get an acknowledgment within a few days. Valid reports get a
coordinated fix and advisory credit.

## Scope

- **In scope:** the `sast-triage` binary (`cmd/`, `internal/`) and the
  workflows under `.github/workflows/`.
- **Out of scope:** `demo/` and `testdata/` are intentionally vulnerable by
  design — they are the triage pipeline's proof-of-life and test targets, not
  defects. Please don't report findings in them.
