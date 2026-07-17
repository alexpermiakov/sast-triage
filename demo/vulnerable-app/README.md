# vulnerable-app — DO NOT DEPLOY

An intentionally vulnerable Go app used only as a target for `sast-triage`'s
daily demo run. Every package here contains a real, exploitable bug on purpose.

Each vulnerability class lives in its own package (`sql_injection/`, `ssrf/`,
…), materialized from a template in [`vulns/`](vulns/) by
[`../inject.sh`](../inject.sh). The injector adds **one class per day** (chosen
by day of the year), so findings accumulate as committed code rather than
overwriting a single file — which keeps the committed verdict cache
(`demo/triage-cache.json`) coherent: every cached verdict maps to code that is
actually present and reviewable in the diff. After five days all classes are
present and further runs are cache hits.

This is a separate Go module (`example.com/vulnerable-demo`) so it stays out of
the main project's `go build ./...`, `go vet ./...`, and test runs.
