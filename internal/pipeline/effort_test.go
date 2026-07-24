package pipeline

import (
	"testing"

	"github.com/alexpermiakov/sast-triage/internal/cache"
)

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

// The preset names live here and their ordering lives in internal/cache, which
// uses it to decide whether a cached verdict was reached at lower depth than
// this run offers. Two lists that must agree and cannot import each other, so
// the agreement is pinned here: an unranked preset silently stops triggering
// re-triage, which is a suppression surviving an upgrade that should have
// re-earned it.
func TestEffortPresetsAreRanked(t *testing.T) {
	for i, name := range EffortNames {
		if _, err := EffortPreset(name); err != nil {
			t.Errorf("EffortNames has %q but EffortPreset rejects it: %v", name, err)
		}
		rank := cache.EffortRank(name)
		if rank == 0 {
			t.Errorf("preset %q has no rank in internal/cache — an upgrade past it would not re-triage", name)
		}
		if i > 0 {
			if prev := cache.EffortRank(EffortNames[i-1]); rank <= prev {
				t.Errorf("rank(%q)=%d is not above rank(%q)=%d; the two orderings disagree",
					name, rank, EffortNames[i-1], prev)
			}
		}
	}
}

// The presets must actually get deeper as they get stronger, or the ranking
// above orders names that mean nothing.
func TestEffortPresetsIncreaseMonotonically(t *testing.T) {
	var prev Effort
	for i, name := range EffortNames {
		e, err := EffortPreset(name)
		if err != nil {
			t.Fatal(err)
		}
		if e.MaxReadLines <= 0 || e.MaxGrepMatches <= 0 || e.TokenBudget <= 0 || e.MaxIterations <= 0 {
			t.Errorf("preset %q has a non-finite bound: %+v", name, e)
		}
		if i > 0 && (e.MaxReadLines <= prev.MaxReadLines || e.TokenBudget <= prev.TokenBudget ||
			e.MaxIterations <= prev.MaxIterations || e.MaxGrepMatches <= prev.MaxGrepMatches) {
			t.Errorf("preset %q (%+v) is not strictly deeper than %q (%+v)", name, e, EffortNames[i-1], prev)
		}
		prev = e
	}
}

func TestParseFailOn(t *testing.T) {
	tests := []struct {
		in            string
		wantUncertain bool
		wantErr       bool
	}{
		{in: "exploitable"},
		{in: "exploitable,uncertain", wantUncertain: true},
		{in: "uncertain,exploitable", wantUncertain: true},
		{in: " exploitable , uncertain ", wantUncertain: true},
		// Dropping exploitable would leave enforce mode unable to fail on a
		// confirmed vulnerability, which is not a configuration anyone means.
		{in: "uncertain", wantErr: true},
		{in: "benign", wantErr: true},
		{in: "exploitable,benign", wantErr: true},
		{in: "", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := ParseFailOn(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseFailOn(%q) err = %v, wantErr %v", tt.in, err, tt.wantErr)
			}
			if err == nil && got.Uncertain != tt.wantUncertain {
				t.Errorf("ParseFailOn(%q).Uncertain = %v, want %v", tt.in, got.Uncertain, tt.wantUncertain)
			}
		})
	}
}

// The shipped default must stay the gate that does not fire on noise.
func TestDefaultFailOnIsExploitableOnly(t *testing.T) {
	if DefaultFailOn.Uncertain {
		t.Error("DefaultFailOn gates on uncertain — that is the gate people disable")
	}
	parsed, err := ParseFailOn("exploitable")
	if err != nil || parsed != DefaultFailOn {
		t.Errorf("ParseFailOn(\"exploitable\") = %+v (err %v), want DefaultFailOn %+v", parsed, err, DefaultFailOn)
	}
}
