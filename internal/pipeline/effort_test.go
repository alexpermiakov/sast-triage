package pipeline

import "testing"

func TestEffortPreset(t *testing.T) {
	for _, tc := range []struct {
		name string
		want Effort
	}{
		{"small", Effort{MaxReadLines: 100, MaxGrepMatches: 25, TokenBudget: 30000, MaxIterations: 6}},
		{"medium", Effort{MaxReadLines: 200, MaxGrepMatches: 50, TokenBudget: 60000, MaxIterations: 10}},
		{"", Effort{MaxReadLines: 200, MaxGrepMatches: 50, TokenBudget: 60000, MaxIterations: 10}},
		{"large", Effort{MaxReadLines: 400, MaxGrepMatches: 100, TokenBudget: 120000, MaxIterations: 15}},
		{"xlarge", Effort{MaxReadLines: 800, MaxGrepMatches: 200, TokenBudget: 240000, MaxIterations: 22}},
	} {
		got, err := EffortPreset(tc.name)
		if err != nil {
			t.Errorf("EffortPreset(%q): %v", tc.name, err)
			continue
		}
		if got != tc.want {
			t.Errorf("EffortPreset(%q) = %+v, want %+v", tc.name, got, tc.want)
		}
		if got.MaxReadLines <= 0 || got.MaxGrepMatches <= 0 || got.TokenBudget <= 0 || got.MaxIterations <= 0 {
			t.Errorf("EffortPreset(%q) has an unbounded dimension: %+v", tc.name, got)
		}
	}
	if _, err := EffortPreset("huge"); err == nil {
		t.Error("unknown preset: want error")
	}
}
