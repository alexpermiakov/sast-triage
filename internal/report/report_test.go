package report

import (
	"strings"
	"testing"
)

func sampleItems() []Item {
	return []Item{
		{
			Fingerprint: "fp-exploit", RuleID: "go.lang.security.sqli.string-formatted-query",
			File: "app/handlers.go", StartLine: 17, EndLine: 17, Severity: 8.6, Level: "error",
			Message: "String-formatted SQL query.", Verdict: "exploitable",
			Reason:   "id flows unsanitized from query param to QueryRow",
			Evidence: []string{"app/handlers.go:16", "app/handlers.go:17-18"},
			IssueRef: 42, TokensUsed: 1200,
		},
		{
			Fingerprint: "fp-benign", RuleID: "go.lang.security.sqli.string-formatted-query",
			File: "app/handlers_test.go", StartLine: 7, EndLine: 7, Severity: 8.6, Level: "error",
			Verdict: "benign", Reason: "test file", Evidence: []string{"app/handlers_test.go:7"},
			ShortCircuit: true,
		},
		{
			Fingerprint: "fp-cached", RuleID: "generic.secrets.hardcoded",
			File: "app/config.go", StartLine: 7, EndLine: 7, Severity: 7.5, Level: "warning",
			Verdict: "benign", Reason: "example credential in sample code",
			Evidence: []string{"app/config.go:7"}, Cached: true,
		},
		{
			Fingerprint: "fp-unc", RuleID: "go.lang.security.audit.xss",
			File: "app/render.go", StartLine: 3, EndLine: 3, Severity: 5.0, Level: "warning",
			Verdict: "uncertain", Reason: "template escaping could not be traced to a sink",
			TokensUsed: 800,
		},
		{
			Fingerprint: "fp-deferred", RuleID: "go.lang.security.audit.path-traversal",
			File: "app/files.go", StartLine: 12, EndLine: 12, Severity: 6.0, Level: "warning",
			Verdict: "uncertain", Reason: "deferred: run budget exhausted", Deferred: true,
		},
	}
}

func TestRenderSectionOrder(t *testing.T) {
	out := Render(sampleItems(), Options{})

	benignAt := strings.Index(out, "## Proposed suppressions")
	exploitAt := strings.Index(out, "## Exploitable")
	uncertainAt := strings.Index(out, "## Uncertain")
	if benignAt < 0 || exploitAt < 0 || uncertainAt < 0 {
		t.Fatalf("missing sections:\n%s", out)
	}
	if !(benignAt < exploitAt && exploitAt < uncertainAt) {
		t.Error("sections must be ordered benign, exploitable, uncertain (scrutiny order)")
	}
	if !strings.Contains(out, "5 findings — **2 benign**") {
		t.Errorf("summary line wrong:\n%s", strings.SplitN(out, "\n", 4)[2])
	}
	if !strings.Contains(out, "1 from cache, 4 newly triaged (2000 tokens)") {
		t.Errorf("cache/token accounting wrong:\n%s", out)
	}
	// Deferred is broken out of uncertain: it is an absent verdict, not one the
	// model failed to reach, and conflating them misreports a budget shortfall
	// as analytical uncertainty.
	if !strings.Contains(out, "**1 uncertain**, **1 deferred** (not triaged)") {
		t.Errorf("deferred must not be counted as uncertain:\n%s", out)
	}
	if !strings.Contains(out, "Issue: #42") {
		t.Error("exploitable item must reference its issue")
	}
	if !strings.Contains(out, "`app/handlers.go:16`") {
		t.Error("without LinkBase, evidence renders as inline code")
	}
	// Within benign: severity 8.6 test-file item before the 7.5 secret.
	if strings.Index(out, "app/handlers_test.go:7") > strings.Index(out, "app/config.go:7") {
		t.Error("sections must sort severity-desc")
	}
}

func TestRenderLinks(t *testing.T) {
	out := Render(sampleItems(), Options{LinkBase: "https://github.com/o/r/blob/abc/"})
	want := "[app/handlers.go:16](https://github.com/o/r/blob/abc/app/handlers.go#L16)"
	if !strings.Contains(out, want) {
		t.Errorf("missing %s in:\n%s", want, out)
	}
	wantRange := "[app/handlers.go:17-18](https://github.com/o/r/blob/abc/app/handlers.go#L17-L18)"
	if !strings.Contains(out, wantRange) {
		t.Errorf("range links must use GitHub #Lx-Ly anchors, want %s", wantRange)
	}
}

func TestRenderEmptySections(t *testing.T) {
	out := Render(nil, Options{})
	if strings.Contains(out, "## ") {
		t.Error("no findings → no sections")
	}
	if !strings.Contains(out, "0 findings") {
		t.Error("summary should still render")
	}
}

// Deferred findings dominate any large-repo run (budget 50 against thousands
// of findings), so they must never render as full stanzas.
func TestRenderDeferredIsIndexedNotStanzas(t *testing.T) {
	out := Render(sampleItems(), Options{})

	if !strings.Contains(out, "## Deferred — not triaged this run (1)") {
		t.Errorf("deferred findings need their own section:\n%s", out)
	}
	if !strings.Contains(out, "- `app/files.go:12` — `go.lang.security.audit.path-traversal` (severity 6.0)") {
		t.Errorf("deferred index must carry location, rule and severity:\n%s", out)
	}
	if strings.Contains(out, "### `app/files.go:12`") {
		t.Error("deferred finding rendered as a full stanza; that is what inflates the report")
	}
	if strings.Contains(out, "verdict source: deferred") {
		t.Error("deferred findings have no verdict to source")
	}
}

func TestRenderDigestPrioritisesExploitable(t *testing.T) {
	out := RenderDigest(sampleItems(), Options{}, 0)

	exploitAt := strings.Index(out, "## Exploitable")
	benignAt := strings.Index(out, "## Proposed suppressions")
	if exploitAt < 0 || benignAt < 0 {
		t.Fatalf("missing sections:\n%s", out)
	}
	if exploitAt > benignAt {
		t.Error("a size-capped surface must lead with exploitable, not with the benign veto queue")
	}
	if !strings.Contains(out, "triage-report.md") {
		t.Error("digest must point at the complete report")
	}
}

// The failure this guards against: byte-truncating the report keeps the
// benign section (rendered first) and discards the exploitable findings.
func TestRenderDigestDropsByPriorityNotByOffset(t *testing.T) {
	items := sampleItems()
	for i := range 400 {
		items = append(items, Item{
			Fingerprint: "fp-bulk", RuleID: "go.lang.security.audit.bulk",
			File: "app/bulk.go", StartLine: i, EndLine: i, Severity: 4.0, Level: "warning",
			Verdict: "benign", Reason: strings.Repeat("padding reason ", 20),
			Evidence: []string{"app/bulk.go:1"},
		})
	}

	const cap = 4000
	out := RenderDigest(items, Options{}, cap)

	if len(out) > cap {
		t.Errorf("digest is %d bytes, over the %d cap", len(out), cap)
	}
	// The one exploitable finding survives 400 benign ones competing for room.
	if !strings.Contains(out, "app/handlers.go:17") {
		t.Errorf("exploitable finding was dropped:\n%s", out)
	}
	if !strings.Contains(out, "omitted") {
		t.Errorf("truncation must be stated, not silent:\n%s", out)
	}
}

// A cap too small for even one stanza still has to report the totals rather
// than emit nothing.
func TestRenderDigestTinyCapKeepsHeadline(t *testing.T) {
	out := RenderDigest(sampleItems(), Options{}, 1)
	if !strings.Contains(out, "5 findings") {
		t.Errorf("headline must survive any cap:\n%s", out)
	}
	if !strings.Contains(out, "triage-report.md") {
		t.Errorf("pointer to the full report must survive any cap:\n%s", out)
	}
}

// The summary is a count and nothing else. Its whole reason to exist is that
// the seed PR body must not restate findings the cache diff below it already
// carries, so a stanza leaking in here is the bug.
func TestRenderSummaryIsCountsOnly(t *testing.T) {
	out := RenderSummary(sampleItems())

	if !strings.Contains(out, "5 findings — **2 benign**") {
		t.Errorf("summary must carry the same accounting as the report:\n%s", out)
	}
	if !strings.Contains(out, "**1 deferred**") {
		t.Errorf("deferred must stay broken out from uncertain:\n%s", out)
	}
	for _, unwanted := range []string{"##", "app/handlers.go", "unsanitized", "Evidence"} {
		if strings.Contains(out, unwanted) {
			t.Errorf("summary must carry no per-finding detail, found %q:\n%s", unwanted, out)
		}
	}
	if n := strings.Count(strings.TrimSpace(out), "\n"); n != 0 {
		t.Errorf("summary must be one line, has %d newlines:\n%s", n+1, out)
	}
}

func TestIssueBody(t *testing.T) {
	it := sampleItems()[0]
	title := IssueTitle(it)
	if title != "[sast-triage] string-formatted-query at app/handlers.go:17" {
		t.Errorf("title = %q", title)
	}
	body := IssueBody(it, Options{LinkBase: "https://github.com/o/r/blob/abc"})
	for _, want := range []string{
		"unsanitized from query param",
		"[app/handlers.go:17](https://github.com/o/r/blob/abc/app/handlers.go#L17)",
		"<!-- sast-triage:fingerprint:fp-exploit -->",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("issue body missing %q:\n%s", want, body)
		}
	}
}
