// Package cache manages .sast-triage/cache.json: verdicts keyed by SARIF
// fingerprint, invalidated by a codeHash over the flagged region plus every
// evidence region.
package cache

import (
	"bytes"
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

// ModelShortCircuit is the model recorded on entries decided by pure rule
// rather than by a model. They are exempt from decider retirement: no model,
// effort or agent-version change bears on a deterministic rule, and retiring
// them would rewrite decidedAt on every run after a swap — churn in the one
// diff that is the audit trail, bought for nothing, since re-deciding a
// short circuit costs no tokens anyway.
const ModelShortCircuit = "rule:short-circuit"

// effortRanks orders the triage-depth presets weakest to strongest. The names
// are pipeline's (see internal/pipeline/effort.go, which owns what each one
// means in read/grep/token/iteration bounds), but the ORDER lives here because
// this is where two of them get compared: an entry's recorded effort against
// the running one. Rank 0 means absent or unknown — see Decider.
//
// TestEffortPresetsAreRanked in internal/pipeline pins the two lists together.
var effortRanks = map[string]int{
	"small":  1,
	"medium": 2,
	"large":  3,
	"xlarge": 4,
}

// EffortRank returns the ordinal for a triage-depth preset name, or 0 when the
// name is empty or not one this binary knows.
func EffortRank(name string) int { return effortRanks[name] }

// Cache is the on-disk triage cache. Entries are keyed by matchBasedId
// fingerprint; all verdict classes are stored (exploitable verdicts are memory
// too — otherwise they would be re-triaged nightly forever).
type Cache struct {
	Version int              `json:"version"`
	Entries map[string]Entry `json:"entries"`
}

// Entry is one cached verdict. A verdict is a fact about the code it read, so
// CodeHash covers the flagged region plus every evidence region.
//
// Model, Effort and AgentVersion are the decider: who reached this verdict, how
// deeply they were allowed to look, and under which generation of the tool's
// own rules. They are recorded on the entry rather than folded into the key,
// because a key carrying them would make every finding a fresh miss on any
// change and re-triage the whole cache. Held as fields, they let Lookup retire
// exactly the entries whose trustworthiness the change actually bears on — see
// Lookup.
type Entry struct {
	RuleID       string   `json:"ruleId"`
	File         string   `json:"file"`
	Verdict      string   `json:"verdict"` // benign | exploitable | uncertain
	Reason       string   `json:"reason"`
	Evidence     []string `json:"evidence"` // "path:line" or "path:line-line"
	CodeHash     string   `json:"codeHash"` // "sha256:..."
	Model        string   `json:"model"`
	Effort       string   `json:"effort,omitempty"`       // triage-depth preset this was decided at
	AgentVersion int      `json:"agentVersion,omitempty"` // policy.AgentVersion at decision time
	DecidedAt    string   `json:"decidedAt"`              // RFC3339
	TokensUsed   int      `json:"tokensUsed"`
	IssueRef     int      `json:"issueRef,omitempty"`
}

// Decider describes who is asking, so Lookup can tell whether an entry was
// decided under weaker conditions than the current run offers.
//
// Effort and AgentVersion are upgrade-only and grandfathered: an entry that
// predates either field (rank 0, version 0) is trusted rather than retired,
// so introducing them costs nothing, and a run at LOWER effort than the cached
// verdict reuses it rather than overwriting good work with cheaper work.
type Decider struct {
	Model        string
	Effort       string
	AgentVersion int
}

// retires reports whether a decider change invalidates this entry.
//
// exploitable never retires. It is the one verdict that fails loudly and costs
// a human a look rather than a shipped vulnerability, and re-running it
// re-confirms at full price in the good case while letting a weaker decider
// overturn a stronger one's work in the bad case.
//
// benign and uncertain both retire, for the same reason from opposite ends:
// benign silently suppresses a finding, so it is the one verdict that must be
// re-earned whenever the thing that earned it changed; uncertain is a
// non-answer, so re-deciding it costs one triage and can only improve on
// nothing. Between them they are every verdict that leaves a finding out of
// the gate's way.
func (e Entry) retires(d Decider) bool {
	if e.Verdict == VerdictExploitable || e.Model == ModelShortCircuit {
		return false
	}
	if e.Model != d.Model {
		return true
	}
	if e.AgentVersion != 0 && e.AgentVersion < d.AgentVersion {
		return true
	}
	if r := EffortRank(e.Effort); r != 0 && EffortRank(d.Effort) > r {
		return true
	}
	return false
}

// Key identifies the finding a lookup is for. The fingerprint is the map key,
// but it is not on its own proof that an entry belongs to the finding asking
// for it: it originates with the scanner, and a scanner emitting a placeholder
// or reusing an id across results hands several distinct findings the same
// key. internal/sarif guarantees uniqueness at ingest; this is that guarantee
// re-checked where the entry is actually trusted, alongside the evidence bar
// and the codeHash, because the same reasoning applies — the file is
// hand-editable in git, and a merge or an edit can pair a fingerprint with an
// entry that was never about this finding.
//
// The failure it forecloses is silent and one-directional: an entry reached
// under the wrong identity is a verdict about other code, and a benign one
// suppresses a finding nobody triaged. RuleID and File are already recorded on
// every entry, so the check costs a comparison and no new state.
type Key struct {
	Fingerprint string
	RuleID      string
	File        string
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

// newEmpty is the cache a run starts from when the file holds no verdicts. It
// carries the current Version so the first Save writes a file this binary can
// read back, rather than a version-0 one that fails the next run's check.
func newEmpty() *Cache {
	return &Cache{Version: Version, Entries: map[string]Entry{}}
}

// Load reads the cache file. A missing file yields an empty cache — first run
// is not an error — and so does an empty one: zero bytes carry exactly as many
// verdicts as no file at all, and every routine way to reach this state is
// benign plumbing rather than damage (`touch` to bootstrap the path, a
// checkout of a branch where the file is absent, an artifact restored empty).
// Failing there strands the run on a file whose only fix is deleting it.
//
// Malformed non-empty JSON stays a hard error. Those bytes are a cache someone
// wrote — plausibly a truncated one with real verdicts in it — and treating it
// as empty would re-triage the whole backlog while hiding the corruption that
// caused it. Neither path can ever yield a verdict, which is the invariant that
// matters: a damaged cache costs money, never safety.
func Load(path string) (*Cache, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return newEmpty(), nil
	}
	if err != nil {
		return nil, fmt.Errorf("read cache: %w", err)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return newEmpty(), nil
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

// Lookup returns the entry for k if it exists, is an entry about k's finding,
// meets the evidence bar, its codeHash still matches the current code, AND a
// model change has not retired it. Any failure to recompute the hash (moved
// file, drifted lines, malformed refs) is a miss: the verdict no longer
// describes the code.
//
// The invariant every miss upholds: a missing, damaged, or unverifiable entry
// causes RE-TRIAGE, never a benign verdict. A wiped or hand-mangled cache costs
// money, never safety — every path out of here that is not a fully verified
// entry returns false, and the caller then pays for a fresh triage.
//
// A change of decider — model, effort preset, or agent version — retires
// benign and uncertain entries and spares exploitable ones. The asymmetry is
// the point, and Entry.retires carries the reasoning. See docs/DESIGN.md.
func (c *Cache) Lookup(k Key, repoRoot string, flagged Region, d Decider) (Entry, bool) {
	e, ok := c.Entries[k.Fingerprint]
	if !ok {
		return Entry{}, false
	}
	// Identity, before anything is believed about the entry: a verdict filed
	// for another rule or another file is not this finding's answer, however
	// well it verifies. See Key.
	if e.RuleID != k.RuleID || e.File != k.File {
		return Entry{}, false
	}
	// Checked before hashing: a retired entry is a miss whatever the code says,
	// and this skips reading every evidence region to prove it.
	if e.retires(d) {
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
