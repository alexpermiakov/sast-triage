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
	if !strings.Contains(out, "4 findings — **2 benign**") {
		t.Errorf("summary line wrong:\n%s", strings.SplitN(out, "\n", 4)[2])
	}
	if !strings.Contains(out, "1 from cache, 3 newly triaged (1200 tokens)") {
		t.Errorf("cache/token accounting wrong:\n%s", out)
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
