package cache

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sampleRoot = "../../testdata/sampleapp"

func TestLoadMissingFile(t *testing.T) {
	c, err := Load(filepath.Join(t.TempDir(), "nope.json"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Version != Version || len(c.Entries) != 0 {
		t.Fatalf("want empty v%d cache, got %+v", Version, c)
	}
}

func TestLoadErrors(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.json")
	os.WriteFile(bad, []byte("{"), 0o644)
	if _, err := Load(bad); err == nil {
		t.Error("corrupt cache: want error")
	}
	v9 := filepath.Join(dir, "v9.json")
	os.WriteFile(v9, []byte(`{"version":9,"entries":{}}`), 0o644)
	if _, err := Load(v9); err == nil || !strings.Contains(err.Error(), "version 9") {
		t.Errorf("version mismatch: got %v", err)
	}
}

func TestSaveLoadRoundtrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cache.json")
	c := &Cache{Version: Version, Entries: map[string]Entry{
		"fp1": {
			RuleID:    "rule.a",
			File:      "app/handlers.go",
			Verdict:   "exploitable",
			Reason:    "unsanitized id reaches QueryRow",
			Evidence:  []string{"app/handlers.go:16", "app/handlers.go:17-18"},
			CodeHash:  "sha256:abc",
			Model:     "test-model",
			DecidedAt: "2026-07-17T00:00:00Z",
		},
	}}
	if err := c.Save(path); err != nil {
		t.Fatal(err)
	}

	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), "\n  \"entries\"") {
		t.Error("cache not indented — must stay human-reviewable in PR diffs")
	}
	if !strings.HasSuffix(string(data), "\n") {
		t.Error("cache missing trailing newline")
	}

	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	e := got.Entries["fp1"]
	if e.Verdict != "exploitable" || len(e.Evidence) != 2 {
		t.Fatalf("roundtrip lost data: %+v", e)
	}
}

func TestSaveDeterministic(t *testing.T) {
	dir := t.TempDir()
	c := &Cache{Version: Version, Entries: map[string]Entry{
		"b": {Verdict: "benign"}, "a": {Verdict: "uncertain"}, "c": {Verdict: "exploitable"},
	}}
	p1, p2 := filepath.Join(dir, "1.json"), filepath.Join(dir, "2.json")
	c.Save(p1)
	c.Save(p2)
	d1, _ := os.ReadFile(p1)
	d2, _ := os.ReadFile(p2)
	if string(d1) != string(d2) {
		t.Error("saves of the same cache differ — diffs must be stable")
	}
}

func TestParseRef(t *testing.T) {
	good := map[string]Region{
		"a/b.go:7":            {File: "a/b.go", Start: 7, End: 7},
		"a/b.go:7-9":          {File: "a/b.go", Start: 7, End: 9},
		"C:/x.go:3":           {File: "C:/x.go", Start: 3, End: 3},
		"pkg/f_test.go:12-12": {File: "pkg/f_test.go", Start: 12, End: 12},
	}
	for ref, want := range good {
		got, err := ParseRef(ref)
		if err != nil || got != want {
			t.Errorf("ParseRef(%q) = %+v, %v; want %+v", ref, got, err, want)
		}
	}
	for _, bad := range []string{"nofile", "a.go:", ":7", "a.go:x", "a.go:5-2", "a.go:0", "a.go:3-x"} {
		if _, err := ParseRef(bad); err == nil {
			t.Errorf("ParseRef(%q): want error", bad)
		}
	}
}

func TestCodeHashDetectsDrift(t *testing.T) {
	flagged := Region{File: "app/handlers.go", Start: 17, End: 17}
	evidence := []string{"app/handlers.go:16", "app/handlers.go:18"}

	h1, err := CodeHash(sampleRoot, flagged, evidence)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h1, "sha256:") {
		t.Fatalf("hash format: %q", h1)
	}
	h2, _ := CodeHash(sampleRoot, flagged, evidence)
	if h1 != h2 {
		t.Fatal("hash not deterministic")
	}

	// Same content, different evidence list → different hash.
	h3, err := CodeHash(sampleRoot, flagged, evidence[:1])
	if err != nil {
		t.Fatal(err)
	}
	if h3 == h1 {
		t.Error("dropping an evidence region did not change the hash")
	}

	// Drift in an EVIDENCE region (not the flagged line) → different hash.
	root := copySampleApp(t)
	hCopy, err := CodeHash(root, flagged, evidence)
	if err != nil {
		t.Fatal(err)
	}
	if hCopy != h1 {
		t.Fatal("identical tree should hash identically")
	}
	mutateLine(t, filepath.Join(root, "app/handlers.go"), 16, "\tid := sanitize(r.URL.Query().Get(\"id\"))")
	hDrift, err := CodeHash(root, flagged, evidence)
	if err != nil {
		t.Fatal(err)
	}
	if hDrift == h1 {
		t.Error("evidence-line drift did not change the hash — invalidation is keyed on the flagged line alone")
	}
}

func TestCodeHashErrors(t *testing.T) {
	flagged := Region{File: "app/handlers.go", Start: 17, End: 17}
	if _, err := CodeHash(sampleRoot, flagged, []string{"missing.go:1"}); err == nil {
		t.Error("missing evidence file: want error")
	}
	if _, err := CodeHash(sampleRoot, flagged, []string{"app/handlers.go:9999"}); err == nil {
		t.Error("out-of-range evidence line: want error")
	}
	if _, err := CodeHash(sampleRoot, flagged, []string{"../../go.mod:1"}); err == nil {
		t.Error("traversal evidence ref: want error")
	}
	if _, err := CodeHash(sampleRoot, flagged, []string{"/etc/hosts:1"}); err == nil {
		t.Error("absolute evidence ref: want error")
	}
}

func TestLookup(t *testing.T) {
	flagged := Region{File: "app/handlers.go", Start: 17, End: 17}
	evidence := []string{"app/handlers.go:16", "app/handlers.go:18"}
	root := copySampleApp(t)
	h, err := CodeHash(root, flagged, evidence)
	if err != nil {
		t.Fatal(err)
	}
	c := &Cache{Version: Version, Entries: map[string]Entry{
		"fp1": {Verdict: "exploitable", Evidence: evidence, CodeHash: h, Model: "model-a"},
	}}

	if _, ok := c.Lookup("unknown", root, flagged, "model-a"); ok {
		t.Error("unknown fingerprint: want miss")
	}
	e, ok := c.Lookup("fp1", root, flagged, "model-a")
	if !ok || e.Verdict != "exploitable" {
		t.Fatalf("want hit, got ok=%v e=%+v", ok, e)
	}

	// Evidence drift → miss, even though the flagged line is unchanged.
	mutateLine(t, filepath.Join(root, "app/handlers.go"), 18, "\trow := s.db.QueryRow(query) // reviewed")
	if _, ok := c.Lookup("fp1", root, flagged, "model-a"); ok {
		t.Error("evidence drift: want miss")
	}
}

// A model change retires uncertain entries and only uncertain entries: a
// non-answer is worth re-deciding, a decided verdict is a claim about the code
// that the identity of the reader does not weaken.
func TestLookupModelChange(t *testing.T) {
	flagged := Region{File: "app/handlers.go", Start: 17, End: 17}
	evidence := []string{"app/handlers.go:16", "app/handlers.go:18"}
	root := copySampleApp(t)
	h, err := CodeHash(root, flagged, evidence)
	if err != nil {
		t.Fatal(err)
	}
	entry := func(verdict, model string) Entry {
		return Entry{Verdict: verdict, Evidence: evidence, CodeHash: h, Model: model}
	}
	c := &Cache{Version: Version, Entries: map[string]Entry{
		"benign":      entry("benign", "model-a"),
		"exploitable": entry("exploitable", "model-a"),
		"uncertain":   entry("uncertain", "model-a"),
		"legacy":      entry("uncertain", ""), // pre-Model cache entry
		"shortcircuit": {Verdict: "benign", Evidence: evidence, CodeHash: h,
			Model: "rule:short-circuit"},
	}}

	for _, tc := range []struct {
		fingerprint, model string
		want               bool
	}{
		{"benign", "model-a", true},
		{"benign", "model-b", true},
		{"exploitable", "model-a", true},
		{"exploitable", "model-b", true},
		{"uncertain", "model-a", true},
		{"uncertain", "model-b", false},
		{"legacy", "model-b", false},
		// Rule-decided, so no model decided it and no model change retires it.
		{"shortcircuit", "model-b", true},
	} {
		if _, ok := c.Lookup(tc.fingerprint, root, flagged, tc.model); ok != tc.want {
			t.Errorf("Lookup(%q, model=%q) ok=%v, want %v", tc.fingerprint, tc.model, ok, tc.want)
		}
	}
}

func copySampleApp(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	err := filepath.Walk(sampleRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(sampleRoot, path)
		dst := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(dst, data, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func mutateLine(t *testing.T, path string, line int, replacement string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(data), "\n")
	if line > len(lines) {
		t.Fatalf("file %s has only %d lines", path, len(lines))
	}
	lines[line-1] = replacement
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0o644); err != nil {
		t.Fatal(err)
	}
}
