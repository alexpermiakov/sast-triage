// Package report renders triage-report.md and GitHub issue bodies. Pure:
// data in, markdown out.
package report

import (
	"fmt"
	"sort"
	"strconv"
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
	TokensIn     int
	TokensOut    int
	IssueRef     int
}

// Options controls rendering. LinkBase, when set, turns file:line references
// into clickable links; it should point at a blob URL for the triaged commit,
// e.g. "https://github.com/owner/repo/blob/<sha>".
type Options struct {
	LinkBase string

	// Model and RunURL are attribution, used by the summary's footer. A
	// reader deciding whether to trust a wall of verdicts needs to know which
	// model produced them and where the full evidence lives; neither is
	// derivable from the items.
	Model  string
	RunURL string

	// RunLabel names what this run was, e.g. "seed". Empty omits it.
	RunLabel string
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

// writeHeadline emits the accounting every rendering shares, so the report,
// the digest and the summary can never disagree about what one run found.
//
// Two lines: what was found, then what it cost. Verdict classes lead with
// exploitable — the reader's first question is whether anything is on fire,
// not how many suppressions are proposed. Deferred is broken out from
// uncertain: "8500 uncertain" reads as 8500 judgements the model could not
// make, when in fact the run never looked at them.
func writeHeadline(b *strings.Builder, items []Item) {
	var benign, exploitable, uncertain, deferred int
	var cached, fresh, tokensIn, tokensOut int
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
		tokensIn += it.TokensIn
		tokensOut += it.TokensOut
	}
	fmt.Fprintf(b, "%d findings — **%d exploitable** · **%d benign** (proposed suppressions) · **%d uncertain**",
		len(items), exploitable, benign, uncertain)
	if deferred > 0 {
		fmt.Fprintf(b, " · **%d deferred** (not triaged)", deferred)
	}
	fmt.Fprintf(b, "\n%d from cache · %d newly triaged · %s in / %s out tokens\n",
		cached, fresh, humanCount(tokensIn), humanCount(tokensOut))
}

// humanCount abbreviates token counts. "162k" is the number a reader acts on;
// the exact 162,314 is noise in a header and is in the report anyway.
func humanCount(n int) string {
	switch {
	case n >= 1_000_000:
		return strings.TrimSuffix(fmt.Sprintf("%.1f", float64(n)/1_000_000), ".0") + "M"
	case n >= 1_000:
		return fmt.Sprintf("%dk", n/1_000)
	default:
		return strconv.Itoa(n)
	}
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

// summaryMaxRows bounds the summary table. Fifteen rows is about what a reader
// takes in without scrolling, and it is the point past which a table stops
// being a summary and becomes the report it links to.
const summaryMaxRows = 15

// RenderSummary renders the run as a headline plus one bounded table: one row
// per verdict, five columns, no evidence lists and no stanzas. It is the seed
// PR body.
//
// The size bound is the point. That body sits directly above a cache diff
// carrying every verdict with its reason and cited evidence, in the one place
// a reviewer can actually edit a verdict — so the body's job is to say what
// the run found and let the diff carry the detail. A digest there restates
// thousands of stanzas where nobody can act on them, and on a real backlog
// blows the 65,536-character body cap doing it.
//
// Rows are ordered by verdict class (exploitable, benign, uncertain), severity
// descending within each. Class beats severity because the classes ask
// different things of the reader: an exploitable finding is work, a benign one
// is a suppression to approve or veto, and mixing them by severity alone means
// the reader sorts them apart by hand. Deferred findings get no row — they
// carry no verdict — and are counted in the headline instead.
//
// Columns run verdict, severity, why, rule, location — left to right in the
// order a reviewer consumes them. The verdict is the claim being made and the
// reason is the argument for it, so both sit ahead of the rule ID and the
// line, which only matter once the reader has decided to go look.
func RenderSummary(items []Item, opts Options) string {
	rows := append(append(filter(items, "exploitable"), filter(items, "benign")...), filter(items, "uncertain")...)

	var b strings.Builder
	b.WriteString("### sast-triage")
	if opts.RunLabel != "" {
		fmt.Fprintf(&b, " · %s", opts.RunLabel)
	}
	b.WriteString("\n\n")
	writeHeadline(&b, items)

	if len(rows) > 0 {
		shown, collapsed := splitRows(rows)
		b.WriteString("\n| verdict | severity | why | rule | location |\n")
		b.WriteString("| --- | --- | --- | --- | --- |\n")
		for _, it := range shown {
			fmt.Fprintf(&b, "| %s | %s | %s | `%s` | %s |\n",
				verdictCell(it.Verdict), severityBucket(it.Severity),
				cell(it.Reason), compactRule(it.RuleID), link(it.Location(), opts))
		}
		if len(collapsed) > 0 {
			fmt.Fprintf(&b, "\n+%d %s — see the report.\n", len(collapsed), bucketList(collapsed))
		}
	}

	fmt.Fprintf(&b, "\nMerging approves the suppressions. Drop any entry from `%s` — it is re-triaged next run.\n", cacheFileName)
	writeSummaryFooter(&b, opts)
	return b.String()
}

// cacheFileName is the default cache path, named in the summary so the
// instruction to drop an entry points at a real file. An operator who moved it
// with -cache reads one wrong path in a PR body; threading the real value
// through three layers to fix that is not worth it.
const cacheFileName = ".sast-triage/cache.json"

// writeSummaryFooter attributes each column to whoever produced it, in column
// order. The verdict is one specific model's — a reader weighing a wall of
// suppressions is entitled to know which, without digging into the workflow
// file — and severity is the scanner's number, not a judgement this tool made.
func writeSummaryFooter(b *strings.Builder, opts Options) {
	verdict := "verdict: sast-triage"
	if opts.Model != "" {
		verdict += " (" + opts.Model + ")"
	}
	parts := []string{verdict, "severity: your scanner"}
	if opts.RunURL != "" {
		parts = append(parts, fmt.Sprintf("[run summary](%s)", opts.RunURL))
		parts = append(parts, fmt.Sprintf("[`triage-report.md`](%s#artifacts)", opts.RunURL))
	} else {
		parts = append(parts, "`triage-report.md` in the run artifacts")
	}
	fmt.Fprintf(b, "\n<sub>%s</sub>\n", strings.Join(parts, " · "))
}

// highSeverity is the critical/high floor, the line splitRows collapses on.
const highSeverity = 7.0

// splitRows decides which rows the table lists and which collapse into the
// count line, preserving the caller's ordering in both.
//
// Under the cap nothing is filtered — a short table costs nothing and a
// medium-severity row is worth seeing when there is room. Over it, SEVERITY
// decides, not position: collapsing the tail of a class-ordered list would
// hide a critical uncertain finding behind a dozen identical medium benign
// ones. Filtering to critical/high instead means the collapse line can only
// ever say "medium/low", which is what makes it safe to skim past.
//
// A run whose findings are all medium or low would filter to an empty table,
// which tells the reader nothing; there, the head of the list is better than
// no rows at all.
func splitRows(rows []Item) (shown, collapsed []Item) {
	if len(rows) <= summaryMaxRows {
		return rows, nil
	}
	for _, it := range rows {
		if it.Severity >= highSeverity {
			shown = append(shown, it)
		} else {
			collapsed = append(collapsed, it)
		}
	}
	if len(shown) == 0 {
		shown, collapsed = rows[:summaryMaxRows], rows[summaryMaxRows:]
	}
	// More critical/high rows than fit: the overflow joins the collapsed set,
	// copied rather than appended in place — shown and the overflow share a
	// backing array, and appending into the tail of one would write over the
	// other.
	if len(shown) > summaryMaxRows {
		overflow := append([]Item{}, shown[summaryMaxRows:]...)
		collapsed = append(overflow, collapsed...)
		shown = shown[:summaryMaxRows]
	}
	return shown, collapsed
}

// severityBucket names the scanner's security-severity score using GitHub Code
// Scanning's thresholds, so a row reads the same as the Security tab a reader
// may have open next to it.
func severityBucket(score float64) string {
	switch {
	case score >= 9.0:
		return "critical"
	case score >= 7.0:
		return "high"
	case score >= 4.0:
		return "medium"
	default:
		return "low"
	}
}

// bucketList names the severities present in the collapsed tail, worst first,
// so "+42 medium/low" says the collapse hid nothing urgent — and says so
// honestly when it did.
func bucketList(items []Item) string {
	seen := map[string]bool{}
	var out []string
	for _, name := range []string{"critical", "high", "medium", "low"} {
		for _, it := range items {
			if severityBucket(it.Severity) == name && !seen[name] {
				seen[name] = true
				out = append(out, name)
			}
		}
	}
	return strings.Join(out, "/")
}

// verdictCell prefixes the verdict with a glyph. The glyph is redundant with
// the word beside it on purpose: it survives being skimmed, and it is what
// makes a wall of green rows with one red one readable at a glance.
func verdictCell(verdict string) string {
	switch verdict {
	case "exploitable":
		return "❌ exploitable"
	case "benign":
		return "✅ benign"
	default:
		return "⚠️ uncertain"
	}
}

// compactRule trims a rule ID to its last three dot-separated segments.
// Scanner rule IDs are namespaced to the point of unreadability
// ("go.lang.security.audit.sqli.string-formatted-query"), and the leading
// segments are the ones every row in the table shares. The tail is what
// distinguishes rules and what an operator greps for.
func compactRule(ruleID string) string {
	parts := strings.Split(ruleID, ".")
	if len(parts) <= 3 {
		return ruleID
	}
	return strings.Join(parts[len(parts)-3:], ".")
}

// maxCellRunes bounds the why column. Reasons are model prose with no length
// contract, so something has to cap them — but the why is the column a reviewer
// actually reads, and 72 runes cut most reasons mid-sentence, before the clause
// naming the sink or the reason it is unreachable. At summaryMaxRows rows this
// costs a few thousand characters against a 65,536-character body cap, which is
// not the binding constraint; readability is.
const maxCellRunes = 240

// cell makes arbitrary text safe and short enough for a markdown table cell: a
// literal pipe would end the column early and a newline would end the row.
func cell(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.Join(strings.Fields(s), " ")
	r := []rune(s)
	if len(r) <= maxCellRunes {
		return s
	}
	// Cut on a word boundary when there is one close to the limit, so the
	// truncation does not land mid-identifier.
	trimmed := strings.TrimRight(string(r[:maxCellRunes]), " ")
	if i := strings.LastIndex(trimmed, " "); i > maxCellRunes-16 {
		trimmed = trimmed[:i]
	}
	return trimmed + "…"
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

// ReviewCommentBody renders one inline pull-request comment for an exploitable
// finding. It is deliberately shorter than IssueBody: this lands in the middle
// of someone's diff, where the finding, the reason, and the evidence to check
// are the whole job — location and severity are already implied by where the
// comment sits. The fingerprint marker rides along so a re-run recognizes its
// own comment instead of posting a second one.
func ReviewCommentBody(it Item, opts Options) string {
	var b strings.Builder
	fmt.Fprintf(&b, "**sast-triage: exploitable** — `%s`\n\n", shortRule(it.RuleID))
	fmt.Fprintf(&b, "%s\n\n", it.Message)
	fmt.Fprintf(&b, "**Why it is exploitable:** %s\n", it.Reason)
	if len(it.Evidence) > 0 {
		b.WriteString("\n**Evidence:**\n")
		for _, ref := range it.Evidence {
			fmt.Fprintf(&b, "- %s\n", link(ref, opts))
		}
	}
	if it.IssueRef != 0 {
		fmt.Fprintf(&b, "\nTracked in #%d.\n", it.IssueRef)
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
