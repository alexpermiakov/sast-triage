// Package sarif parses semgrep SARIF 2.1.0 output into triage findings.
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
	"sort"
	"strconv"
	"strings"
)

// Finding is one SARIF result flattened into the fields triage needs.
type Finding struct {
	RuleID      string
	RuleName    string
	RuleDesc    string
	RuleHelp    string
	Tags        []string
	Severity    float64 // security-severity score, 0-10
	Level       string  // error | warning | note
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
		rules := make(map[string]rule, len(run.Tool.Driver.Rules))
		for _, ru := range run.Tool.Driver.Rules {
			rules[ru.ID] = ru
		}
		for _, res := range run.Results {
			f, err := toFinding(res, rules)
			if err != nil {
				return nil, err
			}
			findings = append(findings, f)
		}
	}

	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Severity != findings[j].Severity {
			return findings[i].Severity > findings[j].Severity
		}
		return findings[i].Fingerprint < findings[j].Fingerprint
	})
	return findings, nil
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
		if f.Level == "" {
			f.Level = ru.DefaultConfiguration.Level
		}
	}
	f.Severity = severityScore(ru, f.Level)

	f.Fingerprint = res.Fingerprints["matchBasedId/v1"]
	if f.Fingerprint == "" {
		f.Fingerprint = syntheticFingerprint(f)
	}

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

func syntheticFingerprint(f Finding) string {
	h := sha256.Sum256([]byte(f.RuleID + "\x00" + f.File + "\x00" + f.Snippet))
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
