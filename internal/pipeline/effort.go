package pipeline

import "fmt"

// Effort is a t-shirt-size preset for triage depth per finding: how much code
// the agent may pull into context and how long it may keep digging. It is
// orthogonal to MaxFindings, which caps breadth per run. Every value stays
// finite at every size — presets scale the bounds, they never remove them.
type Effort struct {
	MaxReadLines   int // per read_file call
	MaxGrepMatches int // per grep_repo call
	TokenBudget    int // per finding, input+output
	MaxIterations  int // agent loop cap per finding
}

// EffortNames lists the presets weakest to strongest. Exported so the ordering
// this package defines can be checked against the ranking internal/cache uses
// to decide whether a cached verdict was reached at lower depth than the
// current run offers — two lists that must agree and live apart, because one is
// about bounds and the other about trust.
var EffortNames = []string{"small", "medium", "large", "xlarge"}

// EffortPreset resolves a preset name; "" means the default, medium, whose
// values match the tool's long-standing hard-coded bounds.
func EffortPreset(name string) (Effort, error) {
	switch name {
	case "small":
		return Effort{MaxReadLines: 100, MaxGrepMatches: 25, TokenBudget: 30000, MaxIterations: 6}, nil
	case "medium", "":
		return Effort{MaxReadLines: 200, MaxGrepMatches: 50, TokenBudget: 60000, MaxIterations: 10}, nil
	case "large":
		return Effort{MaxReadLines: 400, MaxGrepMatches: 100, TokenBudget: 120000, MaxIterations: 15}, nil
	case "xlarge":
		return Effort{MaxReadLines: 800, MaxGrepMatches: 200, TokenBudget: 240000, MaxIterations: 22}, nil
	default:
		return Effort{}, fmt.Errorf("unknown effort %q (want small, medium, large, or xlarge)", name)
	}
}
