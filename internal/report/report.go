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

// Section notes, shared by the full report and the digest so the two never
// drift into describing the same verdict class differently.
const (
	benignNote      = "Each verdict cites the evidence it relies on; veto by rejecting this PR or editing the cache entry."
	exploitableNote = "Also routed to GitHub Issues. PRs approve suppressions; issues own vulnerabilities."
	uncertainNote   = "No verdict met the evidence bar. These stay unsuppressed and are retried when the flagged code changes (or after the cache entry is deleted)."
	deferredNote    = "Not triaged: the run budget was exhausted before these findings were reached. They carry no verdict and stay unsuppressed. The next run picks them up — completed verdicts are cached and free, so a re-run costs only what it newly triages. Raise -max-findings-budget to cover more per run, or narrow the scan."
)

// Render produces triage-report.md, sorted by required human scrutiny:
// proposed suppressions (benign) first — veto must be a 30-second action —
// then exploitable, then uncertain.
//
// Deferred findings render as a compact index, not full stanzas. They carry no
// verdict, and on a large backlog they outnumber real verdicts by orders of
// magnitude; a stanza each buries the analysis in identical boilerplate and
// inflates the report past the size caps of every surface that carries it.
func Render(items []Item, opts Options) string {
	benign := filter(items, "benign")
	exploitable := filter(items, "exploitable")
	uncertain := filter(items, "uncertain")

	var b strings.Builder
	b.WriteString("# SAST triage report\n\n")
	writeHeadline(&b, items)

	section(&b, "Proposed suppressions (benign) — review first", benign, opts, benignNote)
	section(&b, "Exploitable", exploitable, opts, exploitableNote)
	section(&b, "Uncertain", uncertain, opts, uncertainNote)
	deferredSection(&b, filterDeferred(items), opts)

	return b.String()
}

// writeHeadline emits the one-line accounting both renderings share. Deferred
// is broken out from uncertain: "8500 uncertain" reads as 8500 judgements the
// model could not make, when in fact the run never looked at them.
func writeHeadline(b *strings.Builder, items []Item) {
	var benign, exploitable, uncertain, deferred int
	var cached, fresh, tokens int
	for _, it := range items {
		switch {
		case it.Deferred:
			deferred++
		case it.Verdict == "benign":
			benign++
		case it.Verdict == "exploitable":
			exploitable++
		default:
			uncertain++
		}
		if it.Cached {
			cached++
		} else {
			fresh++
		}
		tokens += it.TokensUsed
	}
	fmt.Fprintf(b, "%d findings — **%d benign** (proposed suppressions), **%d exploitable**, **%d uncertain**",
		len(items), benign, exploitable, uncertain)
	if deferred > 0 {
		fmt.Fprintf(b, ", **%d deferred** (not triaged)", deferred)
	}
	fmt.Fprintf(b, ". %d from cache, %d newly triaged (%d tokens).\n", cached, fresh, tokens)
}

func section(b *strings.Builder, title string, items []Item, opts Options, note string) {
	if len(items) == 0 {
		return
	}
	fmt.Fprintf(b, "\n## %s\n\n", title)
	fmt.Fprintf(b, "_%s_\n", note)
	for _, it := range items {
		b.WriteString(itemStanza(it, opts))
	}
}

// deferredSection indexes what the run never reached: location, rule, severity
// — enough to see the shape of the backlog and to spot a high-severity finding
// that a budget bump should reach next run.
func deferredSection(b *strings.Builder, items []Item, opts Options) {
	if len(items) == 0 {
		return
	}
	fmt.Fprintf(b, "\n## Deferred — not triaged this run (%d)\n\n", len(items))
	fmt.Fprintf(b, "_%s_\n\n", deferredNote)
	for _, it := range items {
		fmt.Fprintf(b, "- %s — `%s` (severity %.1f)\n", link(it.Location(), opts), it.RuleID, it.Severity)
	}
}

// itemStanza renders one triaged finding. Shared by the report and the digest
// so a finding reads identically wherever it surfaces.
func itemStanza(it Item, opts Options) string {
	var b strings.Builder
	fmt.Fprintf(&b, "\n### %s — `%s`\n\n", link(it.Location(), opts), it.RuleID)
	badge := "new"
	switch {
	case it.Cached:
		badge = "cached"
	case it.ShortCircuit:
		badge = "short-circuit"
	case it.Deferred:
		badge = "deferred"
	}
	fmt.Fprintf(&b, "- Severity: %.1f (%s) · verdict source: %s\n", it.Severity, it.Level, badge)
	if it.IssueRef > 0 {
		fmt.Fprintf(&b, "- Issue: #%d\n", it.IssueRef)
	}
	fmt.Fprintf(&b, "- Reason: %s\n", it.Reason)
	if len(it.Evidence) > 0 {
		refs := make([]string, len(it.Evidence))
		for i, ref := range it.Evidence {
			refs[i] = link(ref, opts)
		}
		fmt.Fprintf(&b, "- Evidence: %s\n", strings.Join(refs, ", "))
	}
	return b.String()
}

// DefaultDigestBytes bounds the digest to fit every capped GitHub surface it
// targets: PR and issue bodies cap at 65,536 characters, the Actions step
// summary at 1 MiB. One size clears both, and a step summary far larger than
// this is not something a human reads anyway.
const DefaultDigestBytes = 50000

// digestDeferredNote is the report's deferred guidance, trimmed: the digest
// pays for every byte out of the findings budget, and the full rationale is
// one click away in the report.
const digestDeferredNote = "Not triaged: the run budget was exhausted before these were reached. They carry no verdict and stay unsuppressed; the next run picks them up. Raise -max-findings-budget, or narrow the scan."

// RenderDigest renders a byte-bounded variant of the report for surfaces with
// hard size caps — the Actions step summary and PR/issue bodies. Two things
// differ from Render:
//
//   - Section order is inverted: exploitable first. A capped surface must lead
//     with what cannot wait; the benign veto workflow lives in the review PR
//     diff and the full report, neither of which is capped.
//   - What does not fit is dropped by priority, never by byte offset, and the
//     footer states exactly what was dropped. Truncating the report itself
//     would cut from the tail — which is to say it would keep the proposed
//     suppressions and discard the exploitable findings.
//
// maxBytes <= 0 uses DefaultDigestBytes. The headline and footer are always
// emitted, so a pathologically small maxBytes yields those rather than nothing.
func RenderDigest(items []Item, opts Options, maxBytes int) string {
	if maxBytes <= 0 {
		maxBytes = DefaultDigestBytes
	}

	classes := []struct {
		title, note, class string
		items              []Item
	}{
		{"Exploitable", exploitableNote, "exploitable", filter(items, "exploitable")},
		{"Uncertain", uncertainNote, "uncertain", filter(items, "uncertain")},
		{"Proposed suppressions (benign)", benignNote, "benign", filter(items, "benign")},
	}

	// Deferred is a count, never an index: it is the class most likely to be
	// enormous and the one where per-finding detail carries the least.
	var deferredBlock string
	if d := filterDeferred(items); len(d) > 0 {
		deferredBlock = fmt.Sprintf("\n## Deferred — not triaged this run (%d)\n\n_%s_\n", len(d), digestDeferredNote)
	}

	// Reserve the trailer plus the largest footer this input could produce —
	// the one naming every finding as omitted. The real footer's counts only
	// shrink from there, so the cap is a guarantee rather than an estimate.
	var trailer strings.Builder
	trailer.WriteString(deferredBlock)
	worst := map[string]int{}
	for _, c := range classes {
		worst[c.class] = len(c.items)
	}
	writeDigestFooter(&trailer, worst)
	budget := maxBytes - trailer.Len()

	var b strings.Builder
	b.WriteString("# SAST triage report\n\n")
	writeHeadline(&b, items)

	omitted := map[string]int{}
	for _, c := range classes {
		omitted[c.class] = digestSection(&b, c.title, c.note, c.items, opts, budget)
	}

	b.WriteString(deferredBlock)
	writeDigestFooter(&b, omitted)
	return b.String()
}

// digestSection writes as much of one class as the budget allows and returns
// how many items it could not fit.
func digestSection(b *strings.Builder, title, note string, items []Item, opts Options, budget int) int {
	if len(items) == 0 {
		return 0
	}
	header := fmt.Sprintf("\n## %s\n\n_%s_\n", title, note)
	if b.Len()+len(header) > budget {
		return len(items)
	}
	b.WriteString(header)
	for i, it := range items {
		stanza := itemStanza(it, opts)
		if b.Len()+len(stanza) > budget {
			return len(items) - i
		}
		b.WriteString(stanza)
	}
	return 0
}

func writeDigestFooter(b *strings.Builder, omitted map[string]int) {
	var dropped []string
	for _, class := range []string{"exploitable", "uncertain", "benign"} {
		if n := omitted[class]; n > 0 {
			dropped = append(dropped, fmt.Sprintf("%d %s", n, class))
		}
	}
	b.WriteString("\n---\n\n")
	if len(dropped) > 0 {
		fmt.Fprintf(b, "_Digest truncated to fit: %s omitted._ ", strings.Join(dropped, ", "))
	}
	b.WriteString("_The complete report is `triage-report.md` in this run's artifacts._\n")
}

// IssueTitle names the GitHub issue for an exploitable finding.
func IssueTitle(it Item) string {
	return fmt.Sprintf("[sast-triage] %s at %s", shortRule(it.RuleID), it.Location())
}

// FingerprintMarker is the machine-readable marker embedded in every issue
// body, linking the issue back to its cache entry — and letting issue filing
// recognize an already-filed finding when the cache lost its issueRef.
func FingerprintMarker(fingerprint string) string {
	return fmt.Sprintf("<!-- sast-triage:fingerprint:%s -->", fingerprint)
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
	fmt.Fprintf(&b, "\n%s\n", FingerprintMarker(it.Fingerprint))
	return b.String()
}

// filter selects one verdict class. Deferred findings are excluded from every
// verdict class: they were never triaged, so their nominal `uncertain` is an
// absence of a verdict rather than one.
func filter(items []Item, verdict string) []Item {
	return filterBy(items, func(it Item) bool { return !it.Deferred && it.Verdict == verdict })
}

func filterDeferred(items []Item) []Item {
	return filterBy(items, func(it Item) bool { return it.Deferred })
}

// filterBy selects items, sorted severity-desc then by location so every
// rendering is deterministic.
func filterBy(items []Item, keep func(Item) bool) []Item {
	var out []Item
	for _, it := range items {
		if keep(it) {
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
