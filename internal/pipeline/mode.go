package pipeline

import (
	"fmt"
	"strings"
)

// The three run modes. Gating is an explicit input, never derived from scope,
// cache presence, or trigger event — behaviour nobody declared is behaviour
// nobody can debug at 2am.
const (
	// ModeEnforce fails the run on any in-scope exploitable finding.
	ModeEnforce = "enforce"
	// ModeReport triages and publishes, never fails. Nightly full-repo runs.
	ModeReport = "report"
	// ModeBaseline triages everything and gates nothing, to establish the
	// cache a repo has never had. The PR it produces is the security review.
	ModeBaseline = "baseline"
)

// ValidMode reports whether m names a run mode.
func ValidMode(m string) bool {
	switch m {
	case ModeEnforce, ModeReport, ModeBaseline:
		return true
	}
	return false
}

// FailOn is the set of verdict classes the gate fails on. Exploitable is always
// set: a gate that fails on nothing is not a gate, and -mode report already
// expresses "never fail".
type FailOn struct{ Uncertain bool }

// DefaultFailOn is the shipped gate: exploitable only.
//
// Uncertain gating is offered but NOT on by default, including for the CWE
// classes internal/policy bars suppressions for. Those two rules look like they
// belong together and do not. Barring a suppression moves every benign verdict
// in the class to uncertain — the true ones as well as the false ones, since
// policy bars a class rather than a finding — so gating that same class fails
// the build on every finding in it, most of which are fine. That is the gate
// people turn off in week one, and a gate that is off protects nothing.
//
// What the bar already buys without any of that: those findings are no longer
// suppressed, they are in the report, and they are unsuppressed in the SARIF
// uploaded to Code Scanning. The silent path is closed. Failing the build on
// top of it is a separate, louder policy, so it is a separate, explicit input.
var DefaultFailOn = FailOn{}

// ParseFailOn reads the -fail-on flag: "exploitable" or "exploitable,uncertain".
// Exploitable is mandatory in the list rather than implied, so the flag reads as
// the complete set it is rather than a set of extras.
func ParseFailOn(s string) (FailOn, error) {
	f := FailOn{}
	seenExploitable := false
	for _, part := range strings.Split(s, ",") {
		switch strings.TrimSpace(part) {
		case "exploitable":
			seenExploitable = true
		case "uncertain":
			f.Uncertain = true
		case "":
			continue
		default:
			return FailOn{}, fmt.Errorf("unknown -fail-on class %q (want exploitable or exploitable,uncertain)", strings.TrimSpace(part))
		}
	}
	if !seenExploitable {
		return FailOn{}, fmt.Errorf("-fail-on %q must include exploitable", s)
	}
	return f, nil
}

// Gate is the exit decision for a finished run: whether to fail, and the line
// explaining why. It exists as one function so the binary's exit code and the
// tests asserting on it can never drift apart.
//
// Enforce gates on EXPLOITABLE findings in scope — cached ones included — plus
// uncertain ones when the operator asked for that with -fail-on. Decisions
// worth stating:
//
// Exploitable always, uncertain only on request. Gating on uncertain by default
// would fire on every budget exhaustion and every ambiguous finding, and a gate
// that fires on noise is a gate that gets disabled within a week. Where it IS
// requested, budget-exhausted findings are still excluded — see
// Summary.GatingUncertain — because those are the tool failing to look, not a
// claim about the code.
//
// Cached ones included. The obvious alternative — gate only on verdicts decided
// THIS run — makes the exit code a function of cache state, so the same code
// passes or fails depending on whether someone merged a cache update first, and
// a wiped cache turns the whole backlog into "new". Scope is what keeps the
// backlog from blocking a PR: on a diff-scoped run the only exploitable
// findings in play are in files the change touched, and "you edited a file with
// a confirmed exploit in it" is worth a red check.
func Gate(mode string, f FailOn, s Summary) (fail bool, msg string) {
	if mode != ModeEnforce {
		return false, ""
	}
	var counts []string
	if s.Exploitable > 0 {
		counts = append(counts, fmt.Sprintf("%d exploitable", s.Exploitable))
	}
	if f.Uncertain && s.GatingUncertain > 0 {
		counts = append(counts, fmt.Sprintf("%d uncertain", s.GatingUncertain))
	}
	if len(counts) == 0 {
		return false, ""
	}
	found := strings.Join(counts, " and ")
	// A repo that has never been seeded has no reviewed baseline, so every
	// exploitable finding here is arriving for the first time regardless of
	// what the change touched. Failing that run teaches people that the tool
	// is broken; the fix is to seed, and the message says so. This is the one
	// place cache state is consulted, it only ever RELAXES the gate, and it
	// says so out loud rather than silently passing.
	if !s.CacheSeeded {
		return false, fmt.Sprintf(
			"%s finding(s), but this repo has no triage cache yet — reporting instead of failing.\n"+
				"Seed it first (run the triage-seed workflow, or a local run with -mode baseline), review the resulting PR, and merge it.\n"+
				"Until then every run re-triages from scratch and the gate stays advisory.",
			found)
	}
	return true, fmt.Sprintf("%s finding(s) in scope — failing the gate", found)
}
