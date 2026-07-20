// Package cache manages .sast-triage/cache.json: verdicts keyed by SARIF
// fingerprint, invalidated by a codeHash over the flagged region plus every
// evidence region.
package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const Version = 1

// The three verdict classes, spelled out here rather than imported from
// internal/agent because agent imports cache. They live next to the Lookup
// that enforces the rules keyed on them: uncertain is the one class a model
// change invalidates, benign is the one class that must carry evidence, and
// anything outside the set is a damaged entry.
const (
	VerdictBenign      = "benign"
	VerdictExploitable = "exploitable"
	VerdictUncertain   = "uncertain"
)

// Cache is the on-disk triage cache. Entries are keyed by matchBasedId
// fingerprint; all verdict classes are stored (exploitable verdicts are memory
// too — otherwise they would be re-triaged nightly forever).
type Cache struct {
	Version int              `json:"version"`
	Entries map[string]Entry `json:"entries"`
}

// Entry is one cached verdict. A verdict is a fact about the code it read, so
// CodeHash covers the flagged region plus every evidence region. Model is
// load-bearing for uncertain entries only — see Lookup.
type Entry struct {
	RuleID     string   `json:"ruleId"`
	File       string   `json:"file"`
	Verdict    string   `json:"verdict"` // benign | exploitable | uncertain
	Reason     string   `json:"reason"`
	Evidence   []string `json:"evidence"` // "path:line" or "path:line-line"
	CodeHash   string   `json:"codeHash"` // "sha256:..."
	Model      string   `json:"model"`
	DecidedAt  string   `json:"decidedAt"` // RFC3339
	TokensUsed int      `json:"tokensUsed"`
	IssueRef   int      `json:"issueRef,omitempty"`
}

// Region is a contiguous line range in a repo-relative file.
type Region struct {
	File  string
	Start int
	End   int
}

// Ref renders the region as an evidence-style "path:line[-line]" reference.
func (r Region) Ref() string {
	if r.End > r.Start {
		return fmt.Sprintf("%s:%d-%d", r.File, r.Start, r.End)
	}
	return fmt.Sprintf("%s:%d", r.File, r.Start)
}

// Load reads the cache file. A missing file yields an empty cache — first run
// is not an error.
func Load(path string) (*Cache, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &Cache{Version: Version, Entries: map[string]Entry{}}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read cache: %w", err)
	}
	var c Cache
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse cache %s: %w", path, err)
	}
	if c.Version != Version {
		return nil, fmt.Errorf("cache %s has version %d, this binary supports %d", path, c.Version, Version)
	}
	if c.Entries == nil {
		c.Entries = map[string]Entry{}
	}
	return &c, nil
}

// Save writes the cache atomically: indented marshal (the file is
// human-reviewed in PR diffs), temp file in the same directory, rename.
func (c *Cache) Save(path string) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal cache: %w", err)
	}
	data = append(data, '\n')

	// The default cache lives in .sast-triage/, which does not exist on a
	// repo's first run. Create it here rather than making every caller
	// (binary, action, tests) remember to.
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("save cache: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".triage-cache-*.tmp")
	if err != nil {
		return fmt.Errorf("save cache: %w", err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("save cache: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("save cache: %w", err)
	}
	if err := os.Chmod(tmp.Name(), 0o600); err != nil {
		return fmt.Errorf("save cache: %w", err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("save cache: %w", err)
	}
	return nil
}

// Lookup returns the entry for fingerprint if it exists, meets the evidence
// bar, its codeHash still matches the current code, AND a model change has not
// retired it. Any failure to recompute the hash (moved file, drifted lines,
// malformed refs) is a miss: the verdict no longer describes the code.
//
// The invariant every miss upholds: a missing, damaged, or unverifiable entry
// causes RE-TRIAGE, never a benign verdict. A wiped or hand-mangled cache costs
// money, never safety — every path out of here that is not a fully verified
// entry returns false, and the caller then pays for a fresh triage.
//
// Deciding under a different model retires uncertain entries only. uncertain is
// a non-answer, so re-deciding it costs one triage and can only improve on
// nothing. benign and exploitable survive the swap: their invalidation contract
// is cited evidence plus codeHash, which is a claim about the code and says
// nothing about who read it. Re-running them would re-confirm at full price in
// the good case and let a weaker model overturn a stronger one's work in the
// bad case — and the swap direction is not knowable here. See docs/DESIGN.md.
func (c *Cache) Lookup(fingerprint, repoRoot string, flagged Region, model string) (Entry, bool) {
	e, ok := c.Entries[fingerprint]
	if !ok {
		return Entry{}, false
	}
	// Checked before hashing: a retired entry is a miss whatever the code says,
	// and this skips reading every evidence region to prove it.
	if e.Verdict == VerdictUncertain && e.Model != model {
		return Entry{}, false
	}
	// The evidence bar again, at the trust boundary. The agent already refuses
	// to MINT an evidence-free benign, but the cache is a hand-editable file in
	// git: "benign" typed into it by hand, or left behind by a truncating
	// merge, must not suppress a finding on nothing. Re-check on read, where
	// the untrusted input actually enters.
	if e.Verdict == VerdictBenign && len(e.Evidence) == 0 {
		return Entry{}, false
	}
	// An unmodeled verdict string is a damaged entry, not a fourth class.
	switch e.Verdict {
	case VerdictBenign, VerdictExploitable, VerdictUncertain:
	default:
		return Entry{}, false
	}
	if e.CodeHash == "" {
		return Entry{}, false
	}
	h, err := CodeHash(repoRoot, flagged, e.Evidence)
	if err != nil || h != e.CodeHash {
		return Entry{}, false
	}
	return e, true
}

// CodeHash hashes the flagged region plus every evidence region, in order.
// Each region contributes its ref and its exact text, so drift in content,
// location, or the evidence list itself all invalidate the hash.
func CodeHash(repoRoot string, flagged Region, evidence []string) (string, error) {
	regions := make([]Region, 0, 1+len(evidence))
	regions = append(regions, flagged)
	for _, ref := range evidence {
		r, err := ParseRef(ref)
		if err != nil {
			return "", err
		}
		regions = append(regions, r)
	}

	h := sha256.New()
	for _, r := range regions {
		text, err := readRegion(repoRoot, r)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(h, "%s\n%s\x00", r.Ref(), text)
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

// ParseRef parses "path:line" or "path:line-line" evidence references.
func ParseRef(ref string) (Region, error) {
	i := strings.LastIndex(ref, ":")
	if i <= 0 || i == len(ref)-1 {
		return Region{}, fmt.Errorf("evidence ref %q: want path:line or path:line-line", ref)
	}
	file, lines := ref[:i], ref[i+1:]
	start, end := lines, lines
	if j := strings.Index(lines, "-"); j >= 0 {
		start, end = lines[:j], lines[j+1:]
	}
	s, err := strconv.Atoi(start)
	if err != nil {
		return Region{}, fmt.Errorf("evidence ref %q: bad line %q", ref, start)
	}
	e, err := strconv.Atoi(end)
	if err != nil {
		return Region{}, fmt.Errorf("evidence ref %q: bad line %q", ref, end)
	}
	if s < 1 || e < s {
		return Region{}, fmt.Errorf("evidence ref %q: invalid range %d-%d", ref, s, e)
	}
	return Region{File: file, Start: s, End: e}, nil
}

func readRegion(repoRoot string, r Region) (string, error) {
	if filepath.IsAbs(r.File) {
		return "", fmt.Errorf("region %s: absolute paths not allowed", r.Ref())
	}
	clean := filepath.Clean(filepath.FromSlash(r.File))
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("region %s: escapes repo root", r.Ref())
	}
	data, err := os.ReadFile(filepath.Join(repoRoot, clean))
	if err != nil {
		return "", fmt.Errorf("region %s: %w", r.Ref(), err)
	}
	lines := strings.Split(string(data), "\n")
	if r.End > len(lines) {
		return "", fmt.Errorf("region %s: file has only %d lines", r.Ref(), len(lines))
	}
	return strings.Join(lines[r.Start-1:r.End], "\n"), nil
}
