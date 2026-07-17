package sarif

import (
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
