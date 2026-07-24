// Package policy owns the tool's own judgement, as distinct from the model's:
// which findings the agent is not trusted to dismiss, regardless of how well it
// argued the case.
//
// Nothing is barred unless the operator names it. The tool ships no opinion
// about which CWE classes a given repo can afford to auto-suppress, because
// that depends on what the code does and who is on the hook for it — an
// internal batch job and a public payments API do not get the same answer, and
// a list imposed by a binary cannot know which one it is running against. What
// the tool does instead is make the choice cheap to express, immediate to take
// effect, and impossible to get silently wrong. README documents the classes
// measured as unreliable on BenchmarkJava, as a starting point to copy rather
// than a default to discover.
//
// It is pure and has no dependencies — data in, decision out — so the rules can
// be table-tested without an LLM anywhere near them, and so that changing a rule
// is a reviewable diff rather than a prompt edit whose effect nobody can
// measure.
package policy

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// AgentVersion is the generation of the rules under which a verdict was
// REACHED. Cache entries record it, and a bump retires the benign and uncertain
// ones (see cache.Entry.retires) so verdicts reached under superseded rules are
// re-earned rather than inherited. Exploitable entries survive it, as they
// survive every other decider change.
//
// Bump it when a change means a cached verdict would have come out differently
// had it been decided today — a change to the system prompt, the evidence bar,
// the short-circuit tiers.
//
// Do NOT bump it for a change to the no-suppress list. That list is applied when
// a verdict is USED, not when one is minted, so changing it already takes effect
// on entries sitting in the cache: adding a CWE stops those suppressions on the
// very next run, removing one restores them. Bumping on top would re-triage
// every benign entry to produce the same verdict the cache already holds, which
// is then overridden anyway — pure cost, identical outcome. It follows that the
// list is safe to tune per repo without a cache migration.
const AgentVersion = 1

// Policy is one run's no-suppress rules: the CWE classes where a benign verdict
// from the agent is not accepted.
//
// The zero value — and a nil *Policy — bar nothing, which is the shipped
// default. Every method is nil-safe for that reason: "no policy configured" is
// an ordinary state reached by doing nothing, not an error to defend against,
// and a caller that never sets one gets the documented default rather than a
// panic.
type Policy struct {
	barred map[string]bool
}

// New builds a policy from operator configuration. Passing no CWEs yields a
// policy that bars nothing, which is what a run does when the flag is unset.
//
// Malformed input is an error, never a silently ignored entry. A no-suppress
// list is invisible when it works, so a typo that matches nothing would present
// exactly as a repo with no dangerous findings — the one failure this package
// exists to prevent. "CWE-502", "cwe-502" and "502" are all accepted and
// normalised; anything else stops the run.
func New(cwes []string) (*Policy, error) {
	p := &Policy{barred: map[string]bool{}}
	for _, raw := range cwes {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue // a trailing comma is not a mistake worth failing a run over
		}
		cwe, err := normalizeCWE(raw)
		if err != nil {
			return nil, err
		}
		p.barred[cwe] = true
	}
	return p, nil
}

// normalizeCWE accepts "CWE-502", "cwe-502" or "502" and returns "CWE-502".
func normalizeCWE(s string) (string, error) {
	digits := strings.TrimPrefix(strings.ToLower(s), "cwe-")
	n, err := strconv.Atoi(digits)
	if err != nil || n <= 0 {
		return "", fmt.Errorf("bad CWE %q: want a CWE id like CWE-502", s)
	}
	return "CWE-" + strconv.Itoa(n), nil
}

// List returns the barred CWEs for logging what a run is enforcing. A policy
// nobody can see the effect of is one nobody trusts, and "did my flag take?"
// must not require reading a cache diff to answer.
//
// Sorted numerically, not lexically: CWE-78 belongs before CWE-614, and a list
// that puts it after reads like a bug in the thing you are checking for bugs.
func (p *Policy) List() []string {
	if p == nil {
		return nil
	}
	out := make([]string, 0, len(p.barred))
	for cwe := range p.barred {
		out = append(out, cwe)
	}
	sort.Slice(out, func(i, j int) bool { return cweNum(out[i]) < cweNum(out[j]) })
	return out
}

// cweNum is the numeric part of an id this package normalised on the way in, so
// the parse cannot fail here; 0 would only ever order a malformed entry first.
func cweNum(cwe string) int {
	n, _ := strconv.Atoi(strings.TrimPrefix(cwe, "CWE-"))
	return n
}

// SuppressionBarred reports whether any of a finding's CWEs is one the agent
// may not dismiss, and names the first that matched. Ordering follows the
// finding's own CWE list so the explanation names the class a reader would
// expect, not whichever one a map iteration reached first.
func (p *Policy) SuppressionBarred(cwes []string) (string, bool) {
	if p == nil {
		return "", false
	}
	for _, c := range cwes {
		if p.barred[c] {
			return c, true
		}
	}
	return "", false
}

// Apply returns the verdict and reason policy permits for a finding, given what
// the agent concluded. A benign verdict on a barred CWE becomes uncertain; every
// other verdict passes through untouched, as does everything when no policy is
// configured.
//
// Uncertain rather than exploitable: a barred class means the agent's judgement
// is not accepted here, which is a reason to withhold the suppression, not
// evidence of a vulnerability. Claiming one would be the same unearned
// confidence in the other direction, and it would put a finding nobody
// confirmed in front of the gate.
//
// The agent's reasoning is kept rather than discarded. It is often correct — the
// list bars a class, not this finding — and the human who now has to make the
// call is better served reading it than being told only that a rule fired.
func (p *Policy) Apply(verdict, reason string, cwes []string) (string, string, bool) {
	if verdict != "benign" {
		return verdict, reason, false
	}
	cwe, barred := p.SuppressionBarred(cwes)
	if !barred {
		return verdict, reason, false
	}
	return "uncertain", fmt.Sprintf(
		"not auto-suppressed: %s is a class this repo does not accept a benign verdict for. Needs a human. The agent's reasoning was: %s",
		cwe, reason), true
}
