package sarif

import (
	"fmt"
	"sort"
	"strings"
	"testing"
)

func TestParseFileFixture(t *testing.T) {
	findings, err := ParseFile("../../testdata/findings.sarif")
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 3 {
		t.Fatalf("got %d findings, want 3", len(findings))
	}

	// Sorted by security-severity desc: the two 8.6 SQLi results first
	// (fingerprint tie-break), then the 7.5 secret.
	sqli := findings[0]
	if sqli.RuleID != "go.lang.security.audit.database.string-formatted-query.string-formatted-query" {
		t.Errorf("first finding rule = %s, want string-formatted-query", sqli.RuleID)
	}
	if sqli.Severity != 8.6 {
		t.Errorf("severity = %v, want 8.6", sqli.Severity)
	}
	if sqli.File != "app/handlers.go" || sqli.StartLine != 17 {
		t.Errorf("location = %s:%d, want app/handlers.go:17", sqli.File, sqli.StartLine)
	}
	if sqli.Fingerprint != "0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9_0" {
		t.Errorf("fingerprint = %s", sqli.Fingerprint)
	}
	if len(sqli.Trace) != 3 {
		t.Fatalf("trace hops = %d, want 3", len(sqli.Trace))
	}
	if sqli.Trace[0].Line != 16 || !strings.Contains(sqli.Trace[0].Message, "source") {
		t.Errorf("trace[0] = %+v, want source at line 16", sqli.Trace[0])
	}
	if sqli.Trace[2].Line != 18 || !strings.Contains(sqli.Trace[2].Message, "sink") {
		t.Errorf("trace[2] = %+v, want sink at line 18", sqli.Trace[2])
	}
	if !strings.Contains(sqli.RuleDesc, "SQL injection") {
		t.Errorf("rule description missing: %q", sqli.RuleDesc)
	}

	if findings[1].File != "app/handlers_test.go" {
		t.Errorf("second finding file = %s, want app/handlers_test.go", findings[1].File)
	}

	secret := findings[2]
	if secret.Severity != 7.5 {
		t.Errorf("last finding severity = %v, want 7.5 (sorted desc)", secret.Severity)
	}
	if secret.File != "app/config.go" || secret.StartLine != 7 {
		t.Errorf("secret location = %s:%d, want app/config.go:7", secret.File, secret.StartLine)
	}
	hasSecretsTag := false
	for _, tag := range secret.Tags {
		if tag == "secrets" {
			hasSecretsTag = true
		}
	}
	if !hasSecretsTag {
		t.Errorf("secret finding tags = %v, want to include %q", secret.Tags, "secrets")
	}
}

func TestParseErrors(t *testing.T) {
	tests := []struct {
		name, input, wantErr string
	}{
		{"not json", "nope", "decode sarif"},
		{"no runs", `{"version":"2.1.0","runs":[]}`, "no runs"},
		{
			"result without location",
			`{"runs":[{"tool":{"driver":{"name":"x"}},"results":[{"ruleId":"r","message":{"text":"m"}}]}]}`,
			"no locations",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse(strings.NewReader(tt.input))
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestSyntheticFingerprint(t *testing.T) {
	in := `{"runs":[{"tool":{"driver":{"name":"x"}},"results":[
		{"ruleId":"r1","message":{"text":"m"},"locations":[{"physicalLocation":{
			"artifactLocation":{"uri":"./a/b.go"},"region":{"startLine":3,"snippet":{"text":"code"}}}}]}
	]}]}`
	findings, err := Parse(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	f := findings[0]
	if !strings.HasPrefix(f.Fingerprint, "synthetic:") {
		t.Errorf("fingerprint = %q, want synthetic fallback", f.Fingerprint)
	}
	if f.File != "a/b.go" {
		t.Errorf("file = %q, want cleaned a/b.go", f.File)
	}
	if f.EndLine != 3 {
		t.Errorf("endLine = %d, want defaulted to startLine 3", f.EndLine)
	}
	if f.Location() != "a/b.go:3" {
		t.Errorf("Location() = %q", f.Location())
	}
}

// resultJSON builds one SARIF result with the given scanner fingerprint, rule
// and location, for tests about identity rather than parsing.
func resultJSON(fingerprint, ruleID, uri string, line int, snippet string) string {
	return fmt.Sprintf(`{"ruleId":%q,"message":{"text":"m"},
		"fingerprints":{"matchBasedId/v1":%q},
		"locations":[{"physicalLocation":{"artifactLocation":{"uri":%q},
			"region":{"startLine":%d,"snippet":{"text":%q}}}}]}`,
		ruleID, fingerprint, uri, line, snippet)
}

func logJSON(results ...string) string {
	return `{"runs":[{"tool":{"driver":{"name":"x"}},"results":[` +
		strings.Join(results, ",") + `]}]}`
}

// TestFingerprintsAreUnique is the identity invariant: every finding in a run
// gets its own fingerprint, whatever the scanner supplied. Downstream, the
// fingerprint keys the cache, the SARIF verdict map, issue dedupe and comment
// dedupe — so two findings sharing one is not a collision that costs a cache
// hit, it is one finding's verdict becoming another's, and a benign verdict
// crossing over suppresses a finding nobody triaged.
func TestFingerprintsAreUnique(t *testing.T) {
	tests := []struct {
		name string
		in   string
	}{
		{
			// The case that shipped: semgrep run without a platform login
			// stamps this literal on every result, so a non-empty check alone
			// accepted it as an id and every finding shared one cache entry.
			name: "scanner emits a placeholder on every result",
			in: logJSON(
				resultJSON("requires login", "r1", "a.go", 1, "x"),
				resultJSON("requires login", "r2", "b.go", 2, "y"),
				resultJSON("requires login", "r3", "c.go", 3, "z"),
			),
		},
		{
			// Two rules flagging one line: the flagged region is identical, so
			// a shared id would also produce a matching codeHash, and the
			// cache would confirm the wrong verdict rather than reject it.
			name: "one location flagged by two rules under one id",
			in: logJSON(
				resultJSON("dup", "go.string-formatted-query", "a.go", 17, "q := fmt.Sprintf(...)"),
				resultJSON("dup", "go.tainted-sql", "a.go", 17, "q := fmt.Sprintf(...)"),
			),
		},
		{
			name: "no scanner ids at all, repeated snippet in one file",
			in: logJSON(
				resultJSON("", "r1", "a.go", 4, "  interval: weekly"),
				resultJSON("", "r1", "a.go", 14, "  interval: weekly"),
			),
		},
		{
			// Nothing distinguishes these two. They still may not merge.
			name: "results identical in rule, location and text",
			in: logJSON(
				resultJSON("", "r1", "a.go", 7, "same"),
				resultJSON("", "r1", "a.go", 7, "same"),
			),
		},
		{
			name: "some results carry a real id and others do not",
			in: logJSON(
				resultJSON("abc123_0", "r1", "a.go", 1, "x"),
				resultJSON("requires login", "r2", "b.go", 2, "y"),
				resultJSON("", "r3", "c.go", 3, "z"),
			),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings, err := Parse(strings.NewReader(tt.in))
			if err != nil {
				t.Fatal(err)
			}
			seen := map[string]Finding{}
			for _, f := range findings {
				if f.Fingerprint == "" {
					t.Errorf("%s: empty fingerprint", f.Location())
				}
				if prev, dup := seen[f.Fingerprint]; dup {
					t.Errorf("fingerprint %q shared by %s (%s) and %s (%s)",
						f.Fingerprint, prev.Location(), prev.RuleID, f.Location(), f.RuleID)
				}
				seen[f.Fingerprint] = f
			}
			if len(seen) != len(findings) {
				t.Fatalf("%d findings collapsed to %d identities", len(findings), len(seen))
			}
		})
	}
}

// TestUsableScannerIDIsKept: the disambiguation above must not fire on ids
// that are doing their job. A real matchBasedId survives parsing unchanged,
// because it is stable under line drift in a way a synthetic id is not, and
// rewriting it would cost a cache hit on every edit above a finding.
func TestUsableScannerIDIsKept(t *testing.T) {
	in := logJSON(
		resultJSON("abc123_0", "r1", "a.go", 1, "x"),
		resultJSON("def456_0", "r2", "b.go", 2, "y"),
	)
	findings, err := Parse(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	got := []string{findings[0].Fingerprint, findings[1].Fingerprint}
	sort.Strings(got)
	if got[0] != "abc123_0" || got[1] != "def456_0" {
		t.Errorf("fingerprints = %v, want the scanner's own ids", got)
	}
}

// TestSyntheticFingerprintSeparatesLocations: the synthetic id is what a
// finding falls back to, so it has to tell two matches of one rule apart. It
// keys on location precisely because rule + file + snippet did not — repeated
// text in one file is ordinary, not exotic.
func TestSyntheticFingerprintSeparatesLocations(t *testing.T) {
	a := Finding{RuleID: "r1", File: "a.go", StartLine: 4, EndLine: 10, Snippet: "same text"}
	b := a
	b.StartLine, b.EndLine = 14, 20

	if syntheticFingerprint(a) == syntheticFingerprint(b) {
		t.Error("same rule and text at different lines: want distinct fingerprints")
	}
	if syntheticFingerprint(a) != syntheticFingerprint(a) {
		t.Error("synthetic fingerprint is not deterministic")
	}
}
