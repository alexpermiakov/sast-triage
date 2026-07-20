package pipeline

import "fmt"

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

// Gate is the exit decision for a finished run: whether to fail, and the line
// explaining why. It exists as one function so the binary's exit code and the
// tests asserting on it can never drift apart.
//
// Enforce gates on EXPLOITABLE findings in scope — cached ones included, and
// nothing else. Two decisions worth stating:
//
// Exploitable only. Gating on uncertain would fire on every budget exhaustion
// and every ambiguous finding, and a gate that fires on noise is a gate that
// gets disabled within a week. Uncertain findings are loud in the report and
// silent at the exit code, on purpose.
//
// Cached ones included. The obvious alternative — gate only on verdicts decided
// THIS run — makes the exit code a function of cache state, so the same code
// passes or fails depending on whether someone merged a cache update first, and
// a wiped cache turns the whole backlog into "new". Scope is what keeps the
// backlog from blocking a PR: on a diff-scoped run the only exploitable
// findings in play are in files the change touched, and "you edited a file with
// a confirmed exploit in it" is worth a red check.
func Gate(mode string, s Summary) (fail bool, msg string) {
	if mode != ModeEnforce || s.Exploitable == 0 {
		return false, ""
	}
	// A repo that has never been seeded has no reviewed baseline, so every
	// exploitable finding here is arriving for the first time regardless of
	// what the change touched. Failing that run teaches people that the tool
	// is broken; the fix is to seed, and the message says so. This is the one
	// place cache state is consulted, it only ever RELAXES the gate, and it
	// says so out loud rather than silently passing.
	if !s.CacheSeeded {
		return false, fmt.Sprintf(
			"%d exploitable finding(s), but this repo has no triage cache yet — reporting instead of failing.\n"+
				"Seed it first (run the triage-seed workflow, or a local run with -mode baseline), review the resulting PR, and merge it.\n"+
				"Until then every run re-triages from scratch and the gate stays advisory.",
			s.Exploitable)
	}
	return true, fmt.Sprintf("%d exploitable finding(s) in scope — failing the gate", s.Exploitable)
}
