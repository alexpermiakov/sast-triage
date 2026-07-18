package agent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	defaultMaxReadLines   = 200
	defaultMaxGrepMatches = 50
	maxGrepFileSz         = 1 << 20 // skip files over 1 MiB; generated blobs, not evidence
)

// ToolExecutor runs the agent's two read-only tools. Every path is validated
// against the repo root: no absolute paths, no traversal, no symlink escapes.
// Output caps are configurable (effort presets) but always finite.
type ToolExecutor struct {
	root        string // absolute, symlink-resolved
	readLines   int    // max lines per read_file call
	grepMatches int    // max matches per grep_repo call
}

func NewToolExecutor(repoRoot string) (*ToolExecutor, error) {
	abs, err := filepath.Abs(repoRoot)
	if err != nil {
		return nil, fmt.Errorf("tool executor root: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return nil, fmt.Errorf("tool executor root: %w", err)
	}
	return &ToolExecutor{
		root:        resolved,
		readLines:   defaultMaxReadLines,
		grepMatches: defaultMaxGrepMatches,
	}, nil
}

// Execute dispatches one tool call. Errors are returned to the model as
// is_error tool results by the loop; they never abort the triage.
func (e *ToolExecutor) Execute(name string, input json.RawMessage) (string, error) {
	switch name {
	case "read_file":
		var args struct {
			Path      string `json:"path"`
			StartLine int    `json:"start_line"`
		}
		if err := json.Unmarshal(input, &args); err != nil {
			return "", fmt.Errorf("read_file: bad arguments: %w", err)
		}
		return e.readFile(args.Path, args.StartLine)
	case "grep_repo":
		var args struct {
			Pattern string `json:"pattern"`
			Glob    string `json:"glob"`
		}
		if err := json.Unmarshal(input, &args); err != nil {
			return "", fmt.Errorf("grep_repo: bad arguments: %w", err)
		}
		return e.grepRepo(args.Pattern, args.Glob)
	default:
		return "", fmt.Errorf("unknown tool %q", name)
	}
}

func (e *ToolExecutor) readFile(p string, startLine int) (string, error) {
	full, err := e.resolve(p)
	if err != nil {
		return "", err
	}
	data, err := os.ReadFile(full)
	if err != nil {
		return "", fmt.Errorf("read_file %s: %w", p, err)
	}
	if bytes.IndexByte(data, 0) >= 0 {
		return "", fmt.Errorf("read_file %s: binary file", p)
	}

	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if startLine < 1 {
		startLine = 1
	}
	if startLine > len(lines) {
		return "", fmt.Errorf("read_file %s: start_line %d beyond end of file (%d lines)", p, startLine, len(lines))
	}
	end := startLine + e.readLines - 1
	if end > len(lines) {
		end = len(lines)
	}

	var b strings.Builder
	for i := startLine; i <= end; i++ {
		fmt.Fprintf(&b, "%d: %s\n", i, lines[i-1])
	}
	if end < len(lines) {
		fmt.Fprintf(&b, "[truncated at %d lines; file has %d — call read_file again with start_line=%d]\n",
			e.readLines, len(lines), end+1)
	}
	return b.String(), nil
}

func (e *ToolExecutor) grepRepo(pattern, glob string) (string, error) {
	if pattern == "" {
		return "", fmt.Errorf("grep_repo: empty pattern")
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return "", fmt.Errorf("grep_repo: bad pattern: %w", err)
	}

	var b strings.Builder
	matches := 0
	truncated := false
	err = filepath.WalkDir(e.root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable entries are not evidence; skip
		}
		name := d.Name()
		if d.IsDir() {
			if name == ".git" || name == "node_modules" || name == "vendor" {
				return fs.SkipDir
			}
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		rel, err := filepath.Rel(e.root, p)
		if err != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		if glob != "" && !matchGlob(glob, rel) {
			return nil
		}
		if info, err := d.Info(); err != nil || info.Size() > maxGrepFileSz {
			return nil
		}
		data, err := os.ReadFile(p)
		if err != nil || bytes.IndexByte(data, 0) >= 0 {
			return nil
		}
		for i, line := range strings.Split(string(data), "\n") {
			if !re.MatchString(line) {
				continue
			}
			if matches >= e.grepMatches {
				truncated = true
				return filepath.SkipAll
			}
			fmt.Fprintf(&b, "%s:%d: %s\n", rel, i+1, strings.TrimRight(line, "\r"))
			matches++
		}
		return nil
	})
	if err != nil {
		return "", fmt.Errorf("grep_repo: %w", err)
	}
	if matches == 0 {
		return "no matches\n", nil
	}
	if truncated {
		fmt.Fprintf(&b, "[truncated at %d matches — narrow your pattern]\n", e.grepMatches)
	}
	return b.String(), nil
}

// matchGlob matches rel (slash-separated, repo-relative) against a glob:
// patterns containing "/" match the whole path, others match the base name.
func matchGlob(glob, rel string) bool {
	if strings.Contains(glob, "/") {
		ok, err := path.Match(glob, rel)
		return err == nil && ok
	}
	ok, err := path.Match(glob, path.Base(rel))
	return err == nil && ok
}

// resolve validates a repo-relative path and returns its absolute location.
func (e *ToolExecutor) resolve(p string) (string, error) {
	if p == "" {
		return "", fmt.Errorf("empty path")
	}
	if filepath.IsAbs(p) || strings.HasPrefix(p, "~") {
		return "", fmt.Errorf("path %q: only repo-relative paths are allowed", p)
	}
	clean := filepath.Clean(filepath.FromSlash(p))
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path %q: escapes repo root", p)
	}
	full := filepath.Join(e.root, clean)
	resolved, err := filepath.EvalSymlinks(full)
	if err != nil {
		return "", fmt.Errorf("path %q: %w", p, err)
	}
	if resolved != e.root && !strings.HasPrefix(resolved, e.root+string(filepath.Separator)) {
		return "", fmt.Errorf("path %q: escapes repo root", p)
	}
	return resolved, nil
}

// toolDefs declares the agent's read-only tools, with the executor's actual
// caps in the descriptions so the model knows when to page or narrow.
func toolDefs(readLines, grepMatches int) []ToolDef {
	return []ToolDef{
		{
			Name: "read_file",
			Description: fmt.Sprintf("Read a file from the repository with line numbers. "+
				"Returns at most %d lines per call; page with start_line.", readLines),
			Properties: map[string]any{
				"path":       map[string]any{"type": "string", "description": "Repo-relative file path."},
				"start_line": map[string]any{"type": "integer", "description": "1-based first line to read (default 1)."},
			},
			Required: []string{"path"},
		},
		{
			Name: "grep_repo",
			Description: fmt.Sprintf("Search file contents across the repository with a Go (RE2) regular expression. "+
				"Returns matching lines as path:line: text, at most %d matches.", grepMatches),
			Properties: map[string]any{
				"pattern": map[string]any{"type": "string", "description": "RE2 regular expression matched per line."},
				"glob":    map[string]any{"type": "string", "description": "Optional glob filter: match base names (*.go) or full repo-relative paths (internal/*/handlers.go)."},
			},
			Required: []string{"pattern"},
		},
	}
}
