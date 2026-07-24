package policy

import (
	"strings"
	"testing"
)

// mustNew is the configured policy most tests start from.
func mustNew(t *testing.T, cwes ...string) *Policy {
	t.Helper()
	p, err := New(cwes)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// The shipped default bars nothing. The tool has no opinion about which classes
// a repo can afford to auto-suppress until someone tells it — so an operator who
// configures nothing gets the agent's verdicts unmodified, and the mechanism is
// something you opt into rather than discover.
func TestNothingBarredByDefault(t *testing.T) {
	for _, p := range []*Policy{nil, {}, mustNew(t)} {
		if got := p.List(); len(got) != 0 {
			t.Errorf("List() = %v, want empty by default", got)
		}
		// CWE-501 is the class the BenchmarkJava measurement flagged hardest;
		// even that one passes through until it is named.
		if v, _, changed := p.Apply("benign", "r", []string{"CWE-501"}); v != "benign" || changed {
			t.Errorf("Apply on an unconfigured policy = %q (changed=%v), want benign untouched", v, changed)
		}
	}
}

func TestApplyBarsBenignOnConfiguredCWEs(t *testing.T) {
	tests := []struct {
		name        string
		verdict     string
		cwes        []string
		wantVerdict string
		wantChanged bool
	}{
		{
			name:        "benign on a barred CWE becomes uncertain",
			verdict:     "benign",
			cwes:        []string{"CWE-501"},
			wantVerdict: "uncertain",
			wantChanged: true,
		},
		{
			name:        "barred CWE anywhere in the list counts",
			verdict:     "benign",
			cwes:        []string{"CWE-20", "CWE-78"},
			wantVerdict: "uncertain",
			wantChanged: true,
		},
		{
			// Barring everything would make the tool useless rather than safe:
			// a class nobody named is a class the agent still gets to decide.
			name:        "benign on an unnamed CWE passes through",
			verdict:     "benign",
			cwes:        []string{"CWE-89"},
			wantVerdict: "benign",
		},
		{
			name:        "no CWE at all passes through",
			verdict:     "benign",
			cwes:        nil,
			wantVerdict: "benign",
		},
		{
			// Policy withholds a suppression; it never manufactures a
			// vulnerability, and it never softens one either.
			name:        "exploitable on a barred CWE is untouched",
			verdict:     "exploitable",
			cwes:        []string{"CWE-78"},
			wantVerdict: "exploitable",
		},
		{
			name:        "uncertain on a barred CWE is untouched",
			verdict:     "uncertain",
			cwes:        []string{"CWE-327"},
			wantVerdict: "uncertain",
		},
	}

	p := mustNew(t, "CWE-501", "CWE-78", "CWE-327")
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, reason, changed := p.Apply(tt.verdict, "the agent's original reasoning", tt.cwes)
			if got != tt.wantVerdict {
				t.Errorf("verdict = %q, want %q", got, tt.wantVerdict)
			}
			if changed != tt.wantChanged {
				t.Errorf("changed = %v, want %v", changed, tt.wantChanged)
			}
			if !tt.wantChanged {
				return
			}
			// The agent's reasoning survives the override: the list bars a
			// class, not this finding, so the human now holding the decision
			// needs to read what the model actually concluded.
			if !strings.Contains(reason, "the agent's original reasoning") {
				t.Errorf("reason = %q, want the agent's own reasoning kept", reason)
			}
			if !strings.Contains(reason, tt.cwes[len(tt.cwes)-1]) {
				t.Errorf("reason = %q, want the barred CWE named", reason)
			}
		})
	}
}

func TestSuppressionBarred(t *testing.T) {
	p := mustNew(t, "CWE-614")
	if _, barred := p.SuppressionBarred([]string{"CWE-89", "CWE-79"}); barred {
		t.Error("a CWE nobody named must not be barred")
	}
	cwe, barred := p.SuppressionBarred([]string{"CWE-614"})
	if !barred || cwe != "CWE-614" {
		t.Errorf("SuppressionBarred(CWE-614) = %q/%v, want it barred", cwe, barred)
	}
}

// The list is the operator's. Naming classes takes effect immediately — policy
// is applied where a verdict is used, so none of this needs a cache migration
// or a re-triage.
func TestNewConfiguration(t *testing.T) {
	t.Run("bars exactly what was named", func(t *testing.T) {
		p := mustNew(t, "CWE-502")
		if v, _, _ := p.Apply("benign", "r", []string{"CWE-502"}); v != "uncertain" {
			t.Error("named CWE does not bar suppression")
		}
		if v, _, _ := p.Apply("benign", "r", []string{"CWE-501"}); v != "benign" {
			t.Error("an unnamed CWE was barred — nothing is implicit")
		}
	})

	t.Run("accepts the spellings people type", func(t *testing.T) {
		p := mustNew(t, "cwe-502", "611", " CWE-1004 ")
		for _, want := range []string{"CWE-502", "CWE-611", "CWE-1004"} {
			if v, _, _ := p.Apply("benign", "r", []string{want}); v != "uncertain" {
				t.Errorf("%s was not registered", want)
			}
		}
	})

	t.Run("deduplicates", func(t *testing.T) {
		if got := mustNew(t, "CWE-502", "cwe-502", "502").List(); len(got) != 1 {
			t.Errorf("List() = %v, want one entry", got)
		}
	})

	// The failure this forecloses is silent: a list that matches nothing looks
	// exactly like a repo with nothing dangerous in it, which is the outcome the
	// whole package exists to prevent. Typos stop the run instead.
	t.Run("rejects malformed input rather than ignoring it", func(t *testing.T) {
		for _, bad := range []string{"CWE", "SQL injection", "CWE-abc", "CWE-0", "-5"} {
			if _, err := New([]string{bad}); err == nil {
				t.Errorf("New(%q) accepted a value that can never match a finding", bad)
			}
		}
	})

	// strings.Split on an unset flag yields [""], which must not be an error —
	// that is the default path, not a mistake.
	t.Run("empty strings are not an error", func(t *testing.T) {
		p, err := New([]string{"CWE-502", "", "  "})
		if err != nil {
			t.Fatalf("splitting an empty flag must not fail the run: %v", err)
		}
		if got := p.List(); len(got) != 1 {
			t.Errorf("List() = %v, want just CWE-502", got)
		}
	})
}

// The active list is operator-facing output, so its order has to look
// deliberate: CWE-78 before CWE-614, not after it as a string sort would have.
func TestListSortsNumerically(t *testing.T) {
	got := mustNew(t, "CWE-1004", "CWE-79", "CWE-614", "CWE-78").List()
	want := []string{"CWE-78", "CWE-79", "CWE-614", "CWE-1004"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("List() = %v, want %v", got, want)
	}
}

// AgentVersion is load-bearing for cache invalidation: entries record it, and a
// bump retires the benign and uncertain ones. Zero would mean "absent", which
// cache.Entry.retires grandfathers, so a zero version would silently disable
// every retirement this constant exists to trigger.
func TestAgentVersionIsNonZero(t *testing.T) {
	if AgentVersion <= 0 {
		t.Fatalf("AgentVersion = %d, want a positive version", AgentVersion)
	}
}
