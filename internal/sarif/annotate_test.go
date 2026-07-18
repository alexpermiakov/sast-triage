package sarif

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
)

func TestAnnotate(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/findings.sarif")
	if err != nil {
		t.Fatal(err)
	}
	findings, err := Parse(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) < 3 {
		t.Fatalf("fixture has %d findings, want >= 3", len(findings))
	}

	benign, exploitable, untouched := findings[0], findings[1], findings[2]
	out, err := Annotate(raw, map[string]Triage{
		benign.Fingerprint: {
			Verdict:  "benign",
			Reason:   "sample credential in demo code",
			Evidence: []string{"app/config.go:7"},
			Suppress: true,
		},
		exploitable.Fingerprint: {
			Verdict:  "exploitable",
			Reason:   "id flows unsanitized to QueryRow",
			Evidence: []string{"app/handlers.go:16"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	// The annotated log must still be parseable with identical fingerprints.
	reparsed, err := Parse(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("annotated output does not re-parse: %v", err)
	}
	if len(reparsed) != len(findings) {
		t.Fatalf("re-parse: %d findings, want %d", len(reparsed), len(findings))
	}
	for i := range findings {
		if reparsed[i].Fingerprint != findings[i].Fingerprint {
			t.Errorf("re-parse fingerprint %d drifted", i)
		}
	}

	var doc struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name string `json:"name"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				Fingerprints map[string]string `json:"fingerprints"`
				Properties   struct {
					Triage map[string]any `json:"triage"`
				} `json:"properties"`
				Suppressions []struct {
					Kind          string `json:"kind"`
					Status        string `json:"status"`
					Justification string `json:"justification"`
				} `json:"suppressions"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Version == "" {
		t.Error("top-level version field lost in round trip")
	}
	if doc.Runs[0].Tool.Driver.Name == "" {
		t.Error("tool.driver.name lost in round trip")
	}

	seen := map[string]bool{}
	for _, res := range doc.Runs[0].Results {
		fp := res.Fingerprints["matchBasedId/v1"]
		switch fp {
		case benign.Fingerprint:
			seen["benign"] = true
			if got := res.Properties.Triage["verdict"]; got != "benign" {
				t.Errorf("benign result: triage verdict = %v", got)
			}
			if len(res.Suppressions) != 1 {
				t.Fatalf("benign result: %d suppressions, want 1", len(res.Suppressions))
			}
			s := res.Suppressions[0]
			if s.Kind != "external" || s.Status != "accepted" || s.Justification != "sample credential in demo code" {
				t.Errorf("benign suppression = %+v", s)
			}
		case exploitable.Fingerprint:
			seen["exploitable"] = true
			if got := res.Properties.Triage["verdict"]; got != "exploitable" {
				t.Errorf("exploitable result: triage verdict = %v", got)
			}
			if ev, ok := res.Properties.Triage["evidence"].([]any); !ok || len(ev) != 1 {
				t.Errorf("exploitable result: evidence = %v", res.Properties.Triage["evidence"])
			}
			if len(res.Suppressions) != 0 {
				t.Errorf("exploitable result must not be suppressed")
			}
		case untouched.Fingerprint:
			seen["untouched"] = true
			if res.Properties.Triage != nil {
				t.Errorf("unmatched result gained a triage bag: %v", res.Properties.Triage)
			}
			if len(res.Suppressions) != 0 {
				t.Errorf("unmatched result gained suppressions")
			}
		}
	}
	for _, k := range []string{"benign", "exploitable", "untouched"} {
		if !seen[k] {
			t.Errorf("did not find the %s result in annotated output", k)
		}
	}
}

func TestAnnotateMalformed(t *testing.T) {
	if _, err := Annotate([]byte("{not json"), nil); err == nil {
		t.Fatal("want error on malformed input")
	}
}
