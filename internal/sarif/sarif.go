// Package sarif parses opengrep/semgrep SARIF 2.1.0 output into triage findings.
// It is pure: no I/O beyond reading the given file.
package sarif

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

// Finding is one SARIF result flattened into the fields triage needs.
type Finding struct {
	RuleID      string
	RuleName    string
	RuleDesc    string
	RuleHelp    string
	Tags        []string
	CWEs        []string // normalised "CWE-89" ids parsed from Tags
	Severity    float64  // security-severity score, 0-10
	Level       string   // error | warning | note
	Message     string
	File        string // repo-relative, slash-separated
	StartLine   int
	EndLine     int
	Snippet     string
	Fingerprint string // matchBasedId/v1, or synthesized fallback
	Trace       []TraceHop
}

// TraceHop is one step of a SARIF codeFlows taint trace.
type TraceHop struct {
	File    string
	Line    int
	EndLine int
	Snippet string
	Message string
}

// Location renders the flagged region as "file:line" or "file:line-line".
func (f Finding) Location() string {
	if f.EndLine > f.StartLine {
		return fmt.Sprintf("%s:%d-%d", f.File, f.StartLine, f.EndLine)
	}
	return fmt.Sprintf("%s:%d", f.File, f.StartLine)
}

// ParseFile reads and parses a SARIF log, returning findings sorted by
// security-severity descending (ties broken by fingerprint for determinism).
func ParseFile(p string) ([]Finding, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, fmt.Errorf("open sarif: %w", err)
	}
	defer f.Close()
	return Parse(f)
}

// Parse parses a SARIF 2.1.0 log from r.
func Parse(r io.Reader) ([]Finding, error) {
	var log sarifLog
	if err := json.NewDecoder(r).Decode(&log); err != nil {
		return nil, fmt.Errorf("decode sarif: %w", err)
	}
	if len(log.Runs) == 0 {
		return nil, fmt.Errorf("sarif log has no runs")
	}

	var findings []Finding
	for _, run := range log.Runs {
		found, err := findingsFromRun(run)
		if err != nil {
			return nil, err
		}
		findings = append(findings, found...)
	}

	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Severity != findings[j].Severity {
			return findings[i].Severity > findings[j].Severity
		}
		return findings[i].Fingerprint < findings[j].Fingerprint
	})
	return findings, nil
}

// findingsFromRun flattens one SARIF run into findings, in result order, and
// assigns every one of them a fingerprint unique within the run. The returned
// slice is aligned 1:1 with run.Results; a result that could not be parsed
// yields a zero Finding (empty Fingerprint) at its index and the first such
// failure is returned as err, so a caller may either reject the log (Parse) or
// skip that result and carry on (Annotate).
//
// Uniqueness is established here, once, because identity is load-bearing well
// past this package: it keys the cache, the verdict map that annotates the
// SARIF for Code Scanning, issue dedupe and PR-comment dedupe. Two findings
// sharing a fingerprint do not merely collide in a map — one finding's verdict
// silently becomes another's, and a benign verdict crossing over suppresses a
// finding nobody triaged. Every downstream map inherits the guarantee made
// here rather than restating it.
//
// The scanner's own id is preferred, being stable under line drift in a way
// nothing derivable here is. It is used only when it actually identifies a
// result, which two guards decide:
//
//   - Placeholders. Semgrep run without a platform login emits the literal
//     "requires login" for matchBasedId/v1 on every result — non-empty, so an
//     emptiness check alone lets it through as though it were an id.
//   - Values the run repeats. Whatever a scanner means by an id it gives to
//     several distinct results, it is not identity. It is dropped for every
//     result carrying it rather than just the later ones, so identity never
//     depends on which result the scanner happened to emit first.
//
// Both fall back to the synthetic id, which is content-derived and therefore
// stable under reordering. Results identical in rule, location and text can
// survive even that — nothing about them distinguishes one from the other — so
// they, and only they, take an occurrence suffix.
func findingsFromRun(r run) ([]Finding, error) {
	rules := make(map[string]rule, len(r.Tool.Driver.Rules))
	for _, ru := range r.Tool.Driver.Rules {
		rules[ru.ID] = ru
	}

	findings := make([]Finding, len(r.Results))
	scannerIDs := make(map[string]int, len(r.Results))
	var firstErr error
	for i, res := range r.Results {
		f, err := toFinding(res, rules)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue // leaves the zero Finding at i; the caller decides
		}
		findings[i] = f
		if id := scannerID(res); id != "" {
			scannerIDs[id]++
		}
	}

	taken := make(map[string]bool, len(findings))
	for i := range findings {
		if findings[i].RuleID == "" && findings[i].File == "" {
			continue // unparseable: no identity to assign
		}
		id := scannerID(r.Results[i])
		if id == "" || scannerIDs[id] > 1 {
			id = syntheticFingerprint(findings[i])
		}
		unique := id
		for n := 1; taken[unique]; n++ {
			unique = fmt.Sprintf("%s#%d", id, n)
		}
		taken[unique] = true
		findings[i].Fingerprint = unique
	}
	return findings, firstErr
}

// scannerID returns the scanner's own fingerprint for a result, or "" when the
// value cannot be one. A fingerprint is an opaque token; a value carrying
// whitespace is a sentence addressed to a human — semgrep's "requires login",
// emitted on every result when it runs unauthenticated, is the one that
// prompted this check, and the shape of it generalises past that one string.
func scannerID(res result) string {
	id := strings.TrimSpace(res.Fingerprints["matchBasedId/v1"])
	if id == "" || strings.ContainsFunc(id, unicode.IsSpace) {
		return ""
	}
	return id
}

func toFinding(res result, rules map[string]rule) (Finding, error) {
	if len(res.Locations) == 0 {
		return Finding{}, fmt.Errorf("result for rule %s has no locations", res.RuleID)
	}
	loc := res.Locations[0].PhysicalLocation

	f := Finding{
		RuleID:    res.RuleID,
		Message:   res.Message.Text,
		Level:     res.Level,
		File:      cleanURI(loc.ArtifactLocation.URI),
		StartLine: loc.Region.StartLine,
		EndLine:   loc.Region.EndLine,
		Snippet:   loc.Region.Snippet.Text,
	}
	if f.EndLine == 0 {
		f.EndLine = f.StartLine
	}

	ru, ok := rules[res.RuleID]
	if ok {
		f.RuleName = ru.Name
		f.RuleDesc = ru.FullDescription.Text
		if f.RuleDesc == "" {
			f.RuleDesc = ru.ShortDescription.Text
		}
		f.RuleHelp = ru.Help.Text
		f.Tags = ru.Properties.Tags
		f.CWEs = cwesFromTags(ru.Properties.Tags)
		if f.Level == "" {
			f.Level = ru.DefaultConfiguration.Level
		}
	}
	f.Severity = severityScore(ru, f.Level)

	// Fingerprint is assigned by findingsFromRun, which alone can see whether
	// the scanner's id is unique across the run.

	for _, cf := range res.CodeFlows {
		for _, tf := range cf.ThreadFlows {
			for _, tl := range tf.Locations {
				pl := tl.Location.PhysicalLocation
				hop := TraceHop{
					File:    cleanURI(pl.ArtifactLocation.URI),
					Line:    pl.Region.StartLine,
					EndLine: pl.Region.EndLine,
					Snippet: pl.Region.Snippet.Text,
					Message: tl.Location.Message.Text,
				}
				if hop.EndLine == 0 {
					hop.EndLine = hop.Line
				}
				f.Trace = append(f.Trace, hop)
			}
		}
		break // one flow is enough context for triage; extras repeat the same path
	}
	return f, nil
}

// cwesFromTags pulls CWE identifiers out of a rule's tags, normalised to
// "CWE-89" form, in tag order, deduplicated.
//
// CWE is the one classification that survives a scanner swap: rule ids are
// scanner-specific and change with every ruleset, while the CWE a rule maps to
// travels through SARIF from opengrep, semgrep and CodeQL alike, and means the
// same thing in every language. Policy that has to hold across scanners keys on
// this rather than on a rule id — see internal/policy.
//
// Two tag shapes are in the wild and both are accepted: semgrep and opengrep
// write "CWE-89: Improper Neutralization ...", CodeQL writes
// "external/cwe/cwe-089". Hence the substring scan and the leading-zero strip
// rather than an equality test.
func cwesFromTags(tags []string) []string {
	var out []string
	for _, t := range tags {
		id, ok := parseCWE(t)
		if !ok || slices.Contains(out, id) {
			continue
		}
		out = append(out, id)
	}
	return out
}

func parseCWE(tag string) (string, bool) {
	low := strings.ToLower(tag)
	i := strings.Index(low, "cwe-")
	if i < 0 {
		return "", false
	}
	// A run of digits must follow, and it is the whole number: "cwe-89x" is
	// not a CWE id, so trailing non-digits are only allowed as a separator.
	rest := low[i+len("cwe-"):]
	n := 0
	for n < len(rest) && rest[n] >= '0' && rest[n] <= '9' {
		n++
	}
	if n == 0 {
		return "", false
	}
	num := strings.TrimLeft(rest[:n], "0")
	if num == "" {
		return "", false // "CWE-0" is not an id
	}
	return "CWE-" + num, true
}

// severityScore returns the rule's security-severity property if present,
// otherwise a coarse score derived from the level so sorting stays meaningful.
func severityScore(ru rule, level string) float64 {
	if raw := ru.Properties.SecuritySeverity; raw != nil {
		switch v := raw.(type) {
		case string:
			if s, err := strconv.ParseFloat(v, 64); err == nil {
				return s
			}
		case float64:
			return v
		}
	}
	switch level {
	case "error":
		return 8.0
	case "warning":
		return 5.0
	case "note":
		return 3.0
	}
	return 0
}

// syntheticFingerprint identifies a finding by rule plus location, per
// DESIGN.md, with the snippet folded in so a verdict is not carried across a
// line whose content changed underneath it.
//
// The location is what keeps two matches of one rule in one file apart. Rule,
// file and snippet alone did not: distinct findings hashed identically
// whenever the flagged text repeated, which is common enough (a config block,
// a repeated call shape) to be a routine source of shared identity rather than
// an edge case. Line drift costing a re-triage is the cheaper failure — the
// cache-safety invariant already prices a miss at money, and the alternative
// prices a collision at a suppressed finding.
func syntheticFingerprint(f Finding) string {
	h := sha256.Sum256([]byte(strings.Join([]string{
		f.RuleID,
		f.File,
		strconv.Itoa(f.StartLine),
		strconv.Itoa(f.EndLine),
		f.Snippet,
	}, "\x00")))
	return "synthetic:" + hex.EncodeToString(h[:])
}

func cleanURI(uri string) string {
	uri = strings.TrimPrefix(uri, "file://")
	return path.Clean(strings.TrimPrefix(uri, "./"))
}

// --- raw SARIF subset ---

type sarifLog struct {
	Runs []run `json:"runs"`
}

type run struct {
	Tool    tool     `json:"tool"`
	Results []result `json:"results"`
}

type tool struct {
	Driver driver `json:"driver"`
}

type driver struct {
	Name  string `json:"name"`
	Rules []rule `json:"rules"`
}

type rule struct {
	ID                   string    `json:"id"`
	Name                 string    `json:"name"`
	ShortDescription     text      `json:"shortDescription"`
	FullDescription      text      `json:"fullDescription"`
	DefaultConfiguration levelCfg  `json:"defaultConfiguration"`
	Help                 text      `json:"help"`
	Properties           ruleProps `json:"properties"`
}

type ruleProps struct {
	Tags             []string `json:"tags"`
	SecuritySeverity any      `json:"security-severity"`
}

type levelCfg struct {
	Level string `json:"level"`
}

type text struct {
	Text string `json:"text"`
}

type result struct {
	RuleID       string            `json:"ruleId"`
	Level        string            `json:"level"`
	Message      text              `json:"message"`
	Locations    []location        `json:"locations"`
	Fingerprints map[string]string `json:"fingerprints"`
	CodeFlows    []codeFlow        `json:"codeFlows"`
}

type location struct {
	PhysicalLocation physicalLocation `json:"physicalLocation"`
}

type physicalLocation struct {
	ArtifactLocation artifactLocation `json:"artifactLocation"`
	Region           region           `json:"region"`
}

type artifactLocation struct {
	URI string `json:"uri"`
}

type region struct {
	StartLine int  `json:"startLine"`
	EndLine   int  `json:"endLine"`
	Snippet   text `json:"snippet"`
}

type codeFlow struct {
	ThreadFlows []threadFlow `json:"threadFlows"`
}

type threadFlow struct {
	Locations []threadFlowLocation `json:"locations"`
}

type threadFlowLocation struct {
	Location struct {
		Message          text             `json:"message"`
		PhysicalLocation physicalLocation `json:"physicalLocation"`
	} `json:"location"`
}
