package pipeline

import "testing"

func TestGate(t *testing.T) {
	seeded := func(s Summary) Summary { s.CacheSeeded = true; return s }

	tests := []struct {
		name     string
		mode     string
		summary  Summary
		wantFail bool
		wantMsg  bool
	}{
		{
			name:     "enforce fails on an exploitable finding in scope",
			mode:     ModeEnforce,
			summary:  seeded(Summary{Total: 4, Exploitable: 1}),
			wantFail: true,
			wantMsg:  true,
		},
		{
			// The behaviour the old -fail-on-new-exploitable got wrong: a
			// cached exploitable in a file the change touched is still an
			// exploitable in that change's scope. Whether someone merged a
			// cache update first must not decide the exit code.
			name:     "enforce fails on a cached exploitable, not only a fresh one",
			mode:     ModeEnforce,
			summary:  seeded(Summary{Total: 2, Exploitable: 1, Cached: 2, NewExploitable: 0}),
			wantFail: true,
			wantMsg:  true,
		},
		{
			// The gate people do not disable.
			name:     "enforce ignores uncertain and benign",
			mode:     ModeEnforce,
			summary:  seeded(Summary{Total: 30, Benign: 20, Uncertain: 10, Deferred: 5}),
			wantFail: false,
		},
		{
			// Unseeded repo: report the findings, explain the fix, do not fail.
			// The one place cache state is read, and it only relaxes the gate.
			name:     "enforce degrades to advisory on an unseeded repo",
			mode:     ModeEnforce,
			summary:  Summary{Total: 40, Exploitable: 3, CacheSeeded: false},
			wantFail: false,
			wantMsg:  true,
		},
		{
			name:    "report never fails",
			mode:    ModeReport,
			summary: seeded(Summary{Total: 9, Exploitable: 9}),
		},
		{
			name:    "baseline never fails",
			mode:    ModeBaseline,
			summary: Summary{Total: 400, Exploitable: 12},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fail, msg := Gate(tt.mode, tt.summary)
			if fail != tt.wantFail {
				t.Errorf("fail = %v, want %v", fail, tt.wantFail)
			}
			if (msg != "") != tt.wantMsg {
				t.Errorf("msg = %q, want message: %v", msg, tt.wantMsg)
			}
		})
	}
}

func TestValidMode(t *testing.T) {
	for _, m := range []string{ModeEnforce, ModeReport, ModeBaseline} {
		if !ValidMode(m) {
			t.Errorf("ValidMode(%q) = false", m)
		}
	}
	for _, m := range []string{"", "ENFORCE", "gate", "fail"} {
		if ValidMode(m) {
			t.Errorf("ValidMode(%q) = true", m)
		}
	}
}
