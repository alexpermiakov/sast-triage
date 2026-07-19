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
- **Out of scope:** `testdata/` is intentionally vulnerable by design — it is
  the triage pipeline's test target, not a defect. Please don't report
  findings in it.
