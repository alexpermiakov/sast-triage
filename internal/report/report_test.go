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
			IssueRef: 42, TokensIn: 1100, TokensOut: 100,
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
			TokensIn: 700, TokensOut: 100,
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
	if !strings.Contains(out, "5 findings — **1 exploitable** · **2 benign**") {
		t.Errorf("summary line wrong:\n%s", strings.SplitN(out, "\n", 4)[2])
	}
	if !strings.Contains(out, "1 from cache · 4 newly triaged · 1k in / 200 out tokens") {
		t.Errorf("cache/token accounting wrong:\n%s", out)
	}
	// Deferred is broken out of uncertain: it is an absent verdict, not one the
	// model failed to reach, and conflating them misreports a budget shortfall
	// as analytical uncertainty.
	if !strings.Contains(out, "**1 uncertain** · **1 deferred** (not triaged)") {
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

func TestRenderSummary(t *testing.T) {
	out := RenderSummary(sampleItems(), Options{
		Model:    "deepseek-v4-flash",
		RunURL:   "https://github.com/o/r/actions/runs/1",
		RunLabel: "seed",
		LinkBase: "https://github.com/o/r/blob/abc",
	})

	for _, want := range []string{
		"### sast-triage · seed",
		"5 findings — **1 exploitable**",
		"| verdict | severity | why | rule | location |",
		"| ❌ exploitable | high |",
		"| ✅ benign | high |",
		"| ⚠️ uncertain | medium |",
		"`security.sqli.string-formatted-query`",
		"[app/handlers.go:17](https://github.com/o/r/blob/abc/app/handlers.go#L17)",
		"verdict: sast-triage (deepseek-v4-flash)",
		"[run summary](https://github.com/o/r/actions/runs/1)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("summary missing %q:\n%s", want, out)
		}
	}
	// Class beats severity: the 8.6 uncertain-free ordering puts every benign
	// row above the uncertain one even though one uncertain outranks nothing.
	if strings.Index(out, "❌ exploitable") > strings.Index(out, "✅ benign") {
		t.Error("exploitable rows must lead the table")
	}
	if strings.Index(out, "✅ benign") > strings.Index(out, "⚠️ uncertain") {
		t.Error("benign rows must precede uncertain ones")
	}
	// Deferred findings carry no verdict, so they get no row — only the
	// headline count. A row for one would invite a reviewer to act on it.
	if strings.Contains(out, "app/files.go") {
		t.Errorf("deferred finding must not get a table row:\n%s", out)
	}
	// Evidence lists and reasons in full belong in the report and the cache
	// diff; the body would be unbounded with them.
	if strings.Contains(out, "app/handlers.go:16") {
		t.Errorf("summary must not carry evidence lists:\n%s", out)
	}
}

// The bound is the whole design: a body that grows with the backlog is the
// thing this replaced. Past the cap, rows collapse into a count that names
// which severities went unlisted.
func TestRenderSummaryBoundsRows(t *testing.T) {
	items := sampleItems()
	for i := range 200 {
		items = append(items, Item{
			Fingerprint: "fp-bulk", RuleID: "go.lang.security.audit.bulk",
			File: "app/bulk.go", StartLine: i, EndLine: i, Severity: 4.0, Level: "warning",
			Verdict: "benign", Reason: "constant argument", Evidence: []string{"app/bulk.go:1"},
		})
	}

	out := RenderSummary(items, Options{})

	if rows := strings.Count(out, "\n| ") - 2; rows > summaryMaxRows { // less header + separator
		t.Errorf("table has %d rows, over the %d cap:\n%s", rows, summaryMaxRows, out)
	}
	// Over the cap, severity filters: the 200 medium bulk findings and the one
	// medium uncertain collapse, the three critical/high rows stay.
	if !strings.Contains(out, "+201 medium — see the report.") {
		t.Errorf("collapsed rows must be counted and their severities named:\n%s", out)
	}
	if strings.Contains(out, "app/bulk.go") {
		t.Errorf("medium rows must collapse once over the cap:\n%s", out)
	}
	// The exploitable finding sorts first, so no cap can drop it.
	if !strings.Contains(out, "❌ exploitable") {
		t.Errorf("exploitable row was collapsed away:\n%s", out)
	}
	if len(out) > 4000 {
		t.Errorf("summary grew to %d bytes on a 205-finding run; it must stay a summary", len(out))
	}
}

// Table cells are model prose: a stray pipe silently eats a column, and an
// unbounded reason turns every row into a paragraph.
func TestSummaryCellsAreSafeAndBounded(t *testing.T) {
	items := []Item{{
		Fingerprint: "fp", RuleID: "r", File: "a.go", StartLine: 1, EndLine: 1,
		Severity: 9.5, Level: "error", Verdict: "exploitable",
		Reason: "pipe | inside\nand a newline, then " + strings.Repeat("very long prose ", 20),
	}}

	out := RenderSummary(items, Options{})

	if !strings.Contains(out, `pipe \| inside`) {
		t.Errorf("pipe in a reason must be escaped, or it ends the column early:\n%s", out)
	}
	if strings.Count(out, "\n| ") != 3 { // header, separator, one row
		t.Errorf("newline in a reason broke the row apart:\n%s", out)
	}
	if !strings.Contains(out, "…") {
		t.Errorf("over-long reason must be truncated:\n%s", out)
	}
	if !strings.Contains(out, "critical") {
		t.Errorf("severity 9.5 must bucket as critical:\n%s", out)
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

// The suppression comment is the answer to "your tool hides real vulns": it
// says, in the PR, exactly what this change proposes to dismiss and why.
func TestSuppressionComment(t *testing.T) {
	items := sampleItems()
	got := SuppressionComment(items, Options{}, "abc123", "https://github.com/o/r/pull/7/files#diff-x")

	// sampleItems has one fresh benign (the short-circuited test file); the
	// other benign is cached, i.e. approved in an earlier PR.
	if !strings.Contains(got, "1 finding suppressed") {
		t.Errorf("comment does not count the fresh suppression:\n%s", got)
	}
	if strings.Contains(got, "app/config.go") {
		t.Error("comment re-lists a cached suppression; only what this change proposes belongs here")
	}
	if !strings.Contains(got, "app/handlers_test.go") {
		t.Errorf("comment omits the fresh suppression:\n%s", got)
	}
	for _, want := range []string{
		"merging approves them",                      // what the reviewer is actually doing
		".sast-triage/cache.json",                    // where to look
		"https://github.com/o/r/pull/7/files#diff-x", // one click to the diff
		SuppressionMarker("abc123"),                  // dedupe on re-run
	} {
		if !strings.Contains(got, want) {
			t.Errorf("comment missing %q:\n%s", want, got)
		}
	}
}

// Silence when there is nothing new to approve: a bot that comments every run
// is one people learn to skip, taking the runs that mattered with it.
func TestSuppressionCommentSilentWithoutFreshSuppressions(t *testing.T) {
	var items []Item
	for _, it := range sampleItems() {
		if it.Verdict == "benign" {
			it.Cached = true
		}
		items = append(items, it)
	}
	if got := SuppressionComment(items, Options{}, "abc123", ""); got != "" {
		t.Errorf("want no comment when nothing new is suppressed, got:\n%s", got)
	}
}

// A policy override is the opposite of a suppression and has to read that way:
// the agent said benign, the tool declined to accept it.
func TestSuppressionCommentReportsPolicyOverrides(t *testing.T) {
	items := []Item{{
		Fingerprint: "fp-over", RuleID: "java.lang.security.trustbound",
		File: "src/Session.java", StartLine: 12, EndLine: 12,
		CWEs: []string{"CWE-501"}, Verdict: "uncertain",
		Reason: "not auto-suppressed: CWE-501 ...", PolicyOverride: true,
	}}
	got := SuppressionComment(items, Options{}, "abc123", "")
	if !strings.Contains(got, "1 finding not auto-suppressed") {
		t.Errorf("override not reported:\n%s", got)
	}
	if strings.Contains(got, "suppressed by this change") {
		t.Errorf("an override is not a suppression:\n%s", got)
	}
}

func TestCacheDiffURL(t *testing.T) {
	if got := CacheDiffURL("", 7, ".sast-triage/cache.json"); got != "" {
		t.Errorf("no repo slug must yield no link, got %q", got)
	}
	if got := CacheDiffURL("o/r", 0, ".sast-triage/cache.json"); got != "" {
		t.Errorf("no PR must yield no link, got %q", got)
	}
	got := CacheDiffURL("o/r", 7, ".sast-triage/cache.json")
	if !strings.HasPrefix(got, "https://github.com/o/r/pull/7/files#diff-") {
		t.Errorf("CacheDiffURL = %q, want the PR files view anchored at the cache file", got)
	}
}
