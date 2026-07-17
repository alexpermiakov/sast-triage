// Package report renders triage-report.md and GitHub issue bodies. Pure:
// data in, markdown out.
package report

import (
	"fmt"
	"sort"
	"strings"
)

// Item is one triaged finding, flattened for rendering. Both cache hits and
// fresh verdicts arrive in this shape.
type Item struct {
	Fingerprint string
	RuleID      string
	File        string
	StartLine   int
	EndLine     int
	Severity    float64
	Level       string
	Message     string

	Verdict      string
	Reason       string
	Evidence     []string
	Cached       bool // verdict came from the cache, not a fresh LLM run
	ShortCircuit bool // decided by pure rule
	Deferred     bool // run budget exhausted before this finding was triaged
	TokensUsed   int
	IssueRef     int
}

// Options controls rendering. LinkBase, when set, turns file:line references
// into clickable links; it should point at a blob URL for the triaged commit,
// e.g. "https://github.com/owner/repo/blob/<sha>".
type Options struct {
	LinkBase string
}

// Location renders the flagged region as "file:line[-line]".
func (it Item) Location() string {
	if it.EndLine > it.StartLine {
		return fmt.Sprintf("%s:%d-%d", it.File, it.StartLine, it.EndLine)
	}
	return fmt.Sprintf("%s:%d", it.File, it.StartLine)
}

// Render produces triage-report.md, sorted by required human scrutiny:
// proposed suppressions (benign) first — veto must be a 30-second action —
// then exploitable, then uncertain.
func Render(items []Item, opts Options) string {
	benign := filter(items, "benign")
	exploitable := filter(items, "exploitable")
	uncertain := filter(items, "uncertain")

	var b strings.Builder
	b.WriteString("# SAST triage report\n\n")

	cached, fresh, tokens := 0, 0, 0
	for _, it := range items {
		if it.Cached {
			cached++
		} else {
			fresh++
		}
		tokens += it.TokensUsed
	}
	fmt.Fprintf(&b, "%d findings — **%d benign** (proposed suppressions), **%d exploitable**, **%d uncertain**. ",
		len(items), len(benign), len(exploitable), len(uncertain))
	fmt.Fprintf(&b, "%d from cache, %d newly triaged (%d tokens).\n", cached, fresh, tokens)

	section(&b, "Proposed suppressions (benign) — review first", benign, opts,
		"Each verdict cites the evidence it relies on; veto by rejecting this PR or editing the cache entry.")
	section(&b, "Exploitable", exploitable, opts,
		"Also routed to GitHub Issues. PRs approve suppressions; issues own vulnerabilities.")
	section(&b, "Uncertain", uncertain, opts,
		"No verdict met the evidence bar. These stay unsuppressed and will be retried when code or budget changes.")

	return b.String()
}

func section(b *strings.Builder, title string, items []Item, opts Options, note string) {
	if len(items) == 0 {
		return
	}
	fmt.Fprintf(b, "\n## %s\n\n", title)
	fmt.Fprintf(b, "_%s_\n", note)
	for _, it := range items {
		fmt.Fprintf(b, "\n### %s — `%s`\n\n", link(it.Location(), opts), it.RuleID)
		badge := "new"
		switch {
		case it.Cached:
			badge = "cached"
		case it.ShortCircuit:
			badge = "short-circuit"
		case it.Deferred:
			badge = "deferred"
		}
		fmt.Fprintf(b, "- Severity: %.1f (%s) · verdict source: %s\n", it.Severity, it.Level, badge)
		if it.IssueRef > 0 {
			fmt.Fprintf(b, "- Issue: #%d\n", it.IssueRef)
		}
		fmt.Fprintf(b, "- Reason: %s\n", it.Reason)
		if len(it.Evidence) > 0 {
			refs := make([]string, len(it.Evidence))
			for i, ref := range it.Evidence {
				refs[i] = link(ref, opts)
			}
			fmt.Fprintf(b, "- Evidence: %s\n", strings.Join(refs, ", "))
		}
	}
}

// IssueTitle names the GitHub issue for an exploitable finding.
func IssueTitle(it Item) string {
	return fmt.Sprintf("[sast-triage] %s at %s", shortRule(it.RuleID), it.Location())
}

// IssueBody renders the GitHub issue body for an exploitable finding. The
// fingerprint marker makes issues greppable back to cache entries.
func IssueBody(it Item, opts Options) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Confirmed by automated triage: **%s**\n\n", it.RuleID)
	fmt.Fprintf(&b, "- Location: %s\n", link(it.Location(), opts))
	fmt.Fprintf(&b, "- Severity: %.1f (%s)\n", it.Severity, it.Level)
	fmt.Fprintf(&b, "- Finding: %s\n\n", it.Message)
	fmt.Fprintf(&b, "**Why it is exploitable:** %s\n", it.Reason)
	if len(it.Evidence) > 0 {
		b.WriteString("\n**Evidence:**\n")
		for _, ref := range it.Evidence {
			fmt.Fprintf(&b, "- %s\n", link(ref, opts))
		}
	}
	fmt.Fprintf(&b, "\n<!-- sast-triage:fingerprint:%s -->\n", it.Fingerprint)
	return b.String()
}

// filter selects one verdict class, sorted severity-desc then by location so
// the report is deterministic.
func filter(items []Item, verdict string) []Item {
	var out []Item
	for _, it := range items {
		if it.Verdict == verdict {
			out = append(out, it)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Severity != out[j].Severity {
			return out[i].Severity > out[j].Severity
		}
		return out[i].Location() < out[j].Location()
	})
	return out
}

// link turns "path:12" / "path:12-20" into a markdown link when a LinkBase is
// configured, otherwise leaves it as inline code.
func link(ref string, opts Options) string {
	if opts.LinkBase == "" {
		return "`" + ref + "`"
	}
	i := strings.LastIndex(ref, ":")
	if i <= 0 {
		return "`" + ref + "`"
	}
	file, lines := ref[:i], ref[i+1:]
	anchor := "#L" + lines
	if j := strings.Index(lines, "-"); j >= 0 {
		anchor = "#L" + lines[:j] + "-L" + lines[j+1:]
	}
	return fmt.Sprintf("[%s](%s/%s%s)", ref, strings.TrimSuffix(opts.LinkBase, "/"), file, anchor)
}

func shortRule(ruleID string) string {
	parts := strings.Split(ruleID, ".")
	return parts[len(parts)-1]
}
