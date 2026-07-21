package cache

import (
	"os"
	"path/filepath"
	"testing"
)

// TestDamagedEntryNeverSuppresses is the cache-safety invariant, written as a
// test because it is the one property a reviewer of this file should be able to
// check in ten seconds:
//
//	A missing, damaged, or unverifiable cache entry causes RE-TRIAGE.
//	It never yields a benign verdict.
//
// The cache is a hand-editable JSON file in git. Every way it can arrive
// wrong — wiped, truncated, merged badly, edited by someone who wanted a
// finding to go away — has to cost money (a fresh triage) and never safety
// (a silent suppression). Each case below is one way it can arrive wrong.
func TestDamagedEntryNeverSuppresses(t *testing.T) {
	flagged := Region{File: "app/handlers.go", Start: 17, End: 17}
	evidence := []string{"app/handlers.go:16", "app/handlers.go:18"}
	root := copySampleApp(t)
	good, err := CodeHash(root, flagged, evidence)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name  string
		entry Entry
	}{
		{
			// The suppression a hand-editor would reach for first.
			name:  "benign with no evidence at all",
			entry: Entry{Verdict: "benign", CodeHash: good},
		},
		{
			name:  "benign with an empty evidence list and a valid hash",
			entry: Entry{Verdict: "benign", Evidence: []string{}, CodeHash: good},
		},
		{
			name:  "hash missing entirely",
			entry: Entry{Verdict: "benign", Evidence: evidence},
		},
		{
			name:  "hash does not match the code",
			entry: Entry{Verdict: "benign", Evidence: evidence, CodeHash: "sha256:deadbeef"},
		},
		{
			name:  "hash is not even a hash",
			entry: Entry{Verdict: "benign", Evidence: evidence, CodeHash: "trust me"},
		},
		{
			name:  "evidence ref points at a file that does not exist",
			entry: Entry{Verdict: "benign", Evidence: []string{"gone.go:1"}, CodeHash: good},
		},
		{
			name:  "evidence ref is unparseable",
			entry: Entry{Verdict: "benign", Evidence: []string{"app/handlers.go"}, CodeHash: good},
		},
		{
			name:  "evidence ref escapes the repo root",
			entry: Entry{Verdict: "benign", Evidence: []string{"../../go.mod:1"}, CodeHash: good},
		},
		{
			name:  "verdict is a string nobody models",
			entry: Entry{Verdict: "safe", Evidence: evidence, CodeHash: good},
		},
		{
			name:  "verdict differs only in case",
			entry: Entry{Verdict: "BENIGN", Evidence: evidence, CodeHash: good},
		},
		{
			name:  "verdict is empty",
			entry: Entry{Evidence: evidence, CodeHash: good},
		},
	}

	id := Key{Fingerprint: "fp1", RuleID: "go.sqli", File: "app/handlers.go"}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Identity is made correct in every case, so no case here can pass
			// for the wrong reason — each entry is damaged on its own axis and
			// must be rejected on that axis, not on a mismatched rule or file.
			tt.entry.RuleID, tt.entry.File = id.RuleID, id.File
			c := &Cache{Version: Version, Entries: map[string]Entry{id.Fingerprint: tt.entry}}
			e, ok := c.Lookup(id, root, flagged, "model-a")
			if ok {
				t.Fatalf("damaged entry returned as a hit: %+v", e)
			}
		})
	}
}

// TestEntryForAnotherFindingNeverSuppresses: a fingerprint collision must not
// hand one finding another's verdict. Scanners do produce colliding ids —
// semgrep emits the literal "requires login" for every result when it runs
// unauthenticated — and internal/sarif now disambiguates them at ingest, but
// the cache is a hand-editable file reached by a key it does not control, so
// it re-checks rather than assuming ingest was the last writer.
//
// The entries below are otherwise flawless: correct evidence, matching hash,
// matching model. Identity is the only thing wrong, and it is enough.
func TestEntryForAnotherFindingNeverSuppresses(t *testing.T) {
	flagged := Region{File: "app/handlers.go", Start: 17, End: 17}
	evidence := []string{"app/handlers.go:16", "app/handlers.go:18"}
	root := copySampleApp(t)
	good, err := CodeHash(root, flagged, evidence)
	if err != nil {
		t.Fatal(err)
	}

	asked := Key{Fingerprint: "shared", RuleID: "go.tainted-sql", File: "app/handlers.go"}
	valid := Entry{Verdict: "benign", Evidence: evidence, CodeHash: good, Model: "model-a"}

	tests := map[string]Entry{
		// Two rules flagging one line: same file, same region, so the hash
		// verifies against the very code the other rule's verdict cited.
		"decided for a different rule at the same location": func() Entry {
			e := valid
			e.RuleID, e.File = "go.string-formatted-query", "app/handlers.go"
			return e
		}(),
		"decided for a different file": func() Entry {
			e := valid
			e.RuleID, e.File = asked.RuleID, "app/config.go"
			return e
		}(),
		"records no identity at all": func() Entry {
			e := valid
			e.RuleID, e.File = "", ""
			return e
		}(),
	}

	for name, entry := range tests {
		t.Run(name, func(t *testing.T) {
			c := &Cache{Version: Version, Entries: map[string]Entry{asked.Fingerprint: entry}}
			if e, ok := c.Lookup(asked, root, flagged, "model-a"); ok {
				t.Fatalf("another finding's verdict returned as a hit: %+v", e)
			}
		})
	}

	// The control: same entry, right identity, hit. Without this the test
	// above would still pass if Lookup simply stopped returning anything.
	entry := valid
	entry.RuleID, entry.File = asked.RuleID, asked.File
	c := &Cache{Version: Version, Entries: map[string]Entry{asked.Fingerprint: entry}}
	if _, ok := c.Lookup(asked, root, flagged, "model-a"); !ok {
		t.Error("matching identity: want hit")
	}
}

// TestWipedCacheCostsMoneyNotSafety: the whole file going missing is the
// loudest version of the same invariant. Every finding comes back for triage;
// nothing arrives pre-suppressed.
func TestWipedCacheCostsMoneyNotSafety(t *testing.T) {
	flagged := Region{File: "app/handlers.go", Start: 17, End: 17}
	root := copySampleApp(t)

	c, err := Load(filepath.Join(t.TempDir(), "gone.json"))
	if err != nil {
		t.Fatalf("a missing cache must load as empty, not fail: %v", err)
	}
	if _, ok := c.Lookup(Key{Fingerprint: "fp1", RuleID: "go.sqli", File: "app/handlers.go"}, root, flagged, "model-a"); ok {
		t.Error("a wiped cache produced a hit")
	}
}

// TestEmptyCacheFileCostsMoneyNotSafety: Load treats a zero-byte file as an
// empty cache so a run is not stranded on it. That recovery must land on the
// same side of the invariant as every other one — an empty cache, not a
// permissive one.
func TestEmptyCacheFileCostsMoneyNotSafety(t *testing.T) {
	flagged := Region{File: "app/handlers.go", Start: 17, End: 17}
	root := copySampleApp(t)

	path := filepath.Join(t.TempDir(), "cache.json")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatalf("an empty cache file must load as empty, not fail: %v", err)
	}
	if _, ok := c.Lookup(Key{Fingerprint: "fp1", RuleID: "go.sqli", File: "app/handlers.go"}, root, flagged, "model-a"); ok {
		t.Error("an empty cache file produced a hit")
	}
}

// TestSaveCreatesCacheDirectory: the default cache path lives in .sast-triage/,
// which does not exist on a repo's first run.
func TestSaveCreatesCacheDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".sast-triage", "cache.json")
	c := &Cache{Version: Version, Entries: map[string]Entry{"fp1": {Verdict: "benign"}}}
	if err := c.Save(path); err != nil {
		t.Fatalf("Save into a missing directory: %v", err)
	}
	if _, err := Load(path); err != nil {
		t.Fatal(err)
	}
}
