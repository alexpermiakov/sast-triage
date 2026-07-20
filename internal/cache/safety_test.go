package cache

import (
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

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Cache{Version: Version, Entries: map[string]Entry{"fp1": tt.entry}}
			e, ok := c.Lookup("fp1", root, flagged, "model-a")
			if ok {
				t.Fatalf("damaged entry returned as a hit: %+v", e)
			}
		})
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
	if _, ok := c.Lookup("fp1", root, flagged, "model-a"); ok {
		t.Error("a wiped cache produced a hit")
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
