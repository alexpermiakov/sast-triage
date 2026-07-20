package sarif

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// Triage is one verdict to attach to a result during annotation, keyed by the
// same fingerprint Parse computes for that result.
type Triage struct {
	Verdict  string // benign | exploitable | uncertain
	Reason   string
	Evidence []string // "path:line" refs cited by the verdict
	Suppress bool     // also add a SARIF suppression (the caller decides, typically benign only)
}

// Annotate returns a copy of the SARIF log in `in` with triage verdicts
// attached: every matched result gains a `properties.triage` bag, and results
// whose Triage has Suppress set additionally gain a SARIF `suppressions`
// entry (kind "external", status "accepted") that downstream consumers apply
// as dismissals. Unmatched results and all fields this package does not model
// pass through byte-for-byte unchanged.
func Annotate(in []byte, verdicts map[string]Triage) ([]byte, error) {
	var log sarifLog
	if err := json.Unmarshal(in, &log); err != nil {
		return nil, fmt.Errorf("annotate: decode sarif: %w", err)
	}

	// Generic parallel decode preserves everything the typed structs drop.
	// UseNumber keeps numeric literals exact through the round trip.
	var doc map[string]any
	dec := json.NewDecoder(bytes.NewReader(in))
	dec.UseNumber()
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("annotate: decode sarif: %w", err)
	}

	rawRuns, _ := doc["runs"].([]any)
	if len(rawRuns) != len(log.Runs) {
		return nil, fmt.Errorf("annotate: malformed runs array")
	}

	for i, run := range log.Runs {
		rawRun, ok := rawRuns[i].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("annotate: malformed run %d", i)
		}
		rawResults, _ := rawRun["results"].([]any)
		if len(rawResults) != len(run.Results) {
			return nil, fmt.Errorf("annotate: malformed results array in run %d", i)
		}
		// Same function Parse uses, so the fingerprints a verdict was filed
		// under are the fingerprints looked up here — including the
		// disambiguation of results the scanner failed to tell apart. An
		// unparseable result yields an empty fingerprint and is passed through
		// untouched; the error is Parse's to report, not annotation's.
		findings, _ := findingsFromRun(run)
		for j, f := range findings {
			if f.Fingerprint == "" {
				continue
			}
			t, ok := verdicts[f.Fingerprint]
			if !ok {
				continue
			}
			rawRes, ok := rawResults[j].(map[string]any)
			if !ok {
				return nil, fmt.Errorf("annotate: malformed result %d in run %d", j, i)
			}
			annotateResult(rawRes, t)
		}
	}

	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("annotate: encode sarif: %w", err)
	}
	return append(out, '\n'), nil
}

func annotateResult(res map[string]any, t Triage) {
	props, _ := res["properties"].(map[string]any)
	if props == nil {
		props = map[string]any{}
	}
	triage := map[string]any{
		"verdict": t.Verdict,
		"reason":  t.Reason,
	}
	if len(t.Evidence) > 0 {
		triage["evidence"] = t.Evidence
	}
	props["triage"] = triage
	res["properties"] = props

	if t.Suppress {
		res["suppressions"] = []any{map[string]any{
			"kind":          "external",
			"status":        "accepted",
			"justification": t.Reason,
		}}
	}
}
