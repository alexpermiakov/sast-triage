package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"path"
	"strings"

	"github.com/alexpermiakov/sast-triage/internal/cache"
	"github.com/alexpermiakov/sast-triage/internal/sarif"
)

const (
	VerdictBenign      = "benign"
	VerdictExploitable = "exploitable"
	VerdictUncertain   = "uncertain"
)

// Verdict is the agent's decision about one finding.
type Verdict struct {
	Verdict  string   `json:"verdict"`
	Reason   string   `json:"reason"`
	Evidence []string `json:"evidence"`

	Tokens Tokens `json:"-"`
	// ToolCalls is how many read_file/grep_repo calls succeeded behind this
	// verdict — the work the model did to earn it, counted separately from the
	// tokens it spent doing so. Rejected calls do not count: an argument the
	// executor refused returned no code, so it is not evidence. Zero on
	// short-circuit and context-free verdicts, which are offered no tools.
	ToolCalls    int  `json:"-"`
	ShortCircuit bool `json:"-"` // decided by pure rule, no LLM call
}

// Tokens is the LLM spend behind one verdict, kept split rather than summed.
// Input and output are priced separately by every provider, and the two move
// for different reasons — input tracks how much code the loop read, output
// tracks how much the model wrote. A single total hides which one to tune.
type Tokens struct{ In, Out int }

func (t Tokens) Total() int { return t.In + t.Out }

func (t *Tokens) add(r *Response) {
	t.In += r.InputTokens
	t.Out += r.OutputTokens
}

// Config bounds the loop. Zero values fall back to the listed defaults.
type Config struct {
	Model            string
	MaxIterations    int // default 10
	TokenBudget      int // per finding, input+output; default 60000
	MaxTokensPerCall int // default 4096
	MaxReadLines     int // per read_file call; default 200
	MaxGrepMatches   int // per grep_repo call; default 50
	// Temperature is the sampling randomness for every call; nil defaults to
	// 0. There is deliberately no flag behind it — see Request.Temperature for
	// why 0 and not the provider default, and why this is a pointer.
	Temperature *float64
}

// Triager runs one bounded loop per finding.
type Triager struct {
	client Client
	exec   *ToolExecutor
	root   string
	cfg    Config
}

func New(client Client, repoRoot string, cfg Config) (*Triager, error) {
	exec, err := NewToolExecutor(repoRoot)
	if err != nil {
		return nil, err
	}
	if cfg.MaxIterations <= 0 {
		cfg.MaxIterations = 10
	}
	if cfg.TokenBudget <= 0 {
		cfg.TokenBudget = 60000
	}
	if cfg.MaxTokensPerCall <= 0 {
		cfg.MaxTokensPerCall = 4096
	}
	if cfg.Temperature == nil {
		zero := 0.0
		cfg.Temperature = &zero
	}
	if cfg.MaxReadLines > 0 {
		exec.readLines = cfg.MaxReadLines
	}
	if cfg.MaxGrepMatches > 0 {
		exec.grepMatches = cfg.MaxGrepMatches
	}
	return &Triager{client: client, exec: exec, root: repoRoot, cfg: cfg}, nil
}

// TriageFinding decides one finding. It returns an error only on transport
// failure (the caller reports those as uncertain but must not cache them);
// every in-loop failure mode — budget exhaustion, malformed verdicts, rejected
// tool calls — resolves to a verdict, fail-closed to "uncertain".
func (t *Triager) TriageFinding(ctx context.Context, f sarif.Finding) (Verdict, error) {
	if v, ok := ShortCircuit(f); ok {
		return v, nil
	}

	tools := toolDefs(t.exec.readLines, t.exec.grepMatches)
	maxIter := t.cfg.MaxIterations
	prompt := buildTriagePrompt(f)
	if isContextFree(f) {
		// The evidence is the snippet itself: one call, no tools.
		tools, maxIter, prompt = nil, 1, contextFreePrompt(f)
	}

	msgs := []Message{{Role: "user", Content: []Block{{Type: "text", Text: prompt}}}}
	var tokens Tokens
	var toolOK, toolFailed int
	retried := false
	nudged := false

	for i := 0; i < maxIter; i++ {
		resp, err := t.client.Complete(ctx, Request{
			Model:       t.cfg.Model,
			System:      systemPrompt,
			Messages:    msgs,
			Tools:       tools,
			Temperature: t.cfg.Temperature,
			MaxTokens:   t.cfg.MaxTokensPerCall,
		})
		if err != nil {
			return Verdict{}, fmt.Errorf("triage finding %s: %w", f.Fingerprint, err)
		}
		tokens.add(resp)

		if calls := toolCalls(resp); len(calls) > 0 {
			msgs = append(msgs, Message{Role: "assistant", Content: resp.Content})
			var results []Block
			for _, c := range calls {
				out, err := t.exec.Execute(c.Name, c.Input)
				if err != nil {
					toolFailed++
					results = append(results, Block{Type: "tool_result", ToolUseID: c.ID, Text: err.Error(), IsError: true})
					continue
				}
				toolOK++
				results = append(results, Block{Type: "tool_result", ToolUseID: c.ID, Text: out})
			}
			msgs = append(msgs, Message{Role: "user", Content: results})
		} else {
			text := responseText(resp)
			v, perr := parseVerdict(text)
			switch {
			case perr == nil && (len(tools) == 0 || toolOK > 0):
				v.Tokens, v.ToolCalls = tokens, toolOK
				return t.validate(v, f), nil

			// Minimum-evidence gate: a verdict reached without opening a single
			// file is the model answering from the prompt — the snippet and the
			// scanner's own trace — which is precisely the claim triage exists
			// to check. Some providers also never emit tool calls at all
			// (thinking-mode models that answer straight through, endpoints that
			// accept the tools array and ignore it); that failure is otherwise
			// silent, because the verdicts it produces look well-formed. Nudge
			// once, then fail closed to uncertain rather than bank an unearned
			// verdict. Never applies where no tools were offered.
			case perr == nil && !nudged:
				nudged = true
				msgs = append(msgs,
					Message{Role: "assistant", Content: []Block{{Type: "text", Text: text}}},
					Message{Role: "user", Content: []Block{{Type: "text", Text: noEvidenceNudge}}},
				)
			case perr == nil:
				return t.uncertain(f, tokens, toolOK, noEvidenceReason(toolFailed)), nil

			case retried:
				return t.uncertain(f, tokens, toolOK, "model did not produce a parseable verdict after retry"), nil
			default:
				retried = true
				msgs = append(msgs,
					Message{Role: "assistant", Content: []Block{{Type: "text", Text: text}}},
					Message{Role: "user", Content: []Block{{Type: "text", Text: "That was not a valid verdict. Reply with ONLY the JSON object: " +
						`{"verdict": "benign|exploitable|uncertain", "reason": "...", "evidence": ["path:line"]}`}}},
				)
			}
		}

		// The budget gates continuing, not finishing. Every further call
		// re-sends the whole conversation, so it costs at least this call's
		// input again plus up to MaxTokensPerCall of output — stop before
		// issuing a call that would blow the budget, not after.
		if tokens.Total()+resp.InputTokens+t.cfg.MaxTokensPerCall > t.cfg.TokenBudget {
			return t.uncertain(f, tokens, toolOK, fmt.Sprintf("token budget exhausted (%d of %d tokens used; the next call would exceed the budget)", tokens.Total(), t.cfg.TokenBudget)), nil
		}
	}

	return t.uncertain(f, tokens, toolOK, fmt.Sprintf("iteration cap (%d) reached without a verdict", maxIter)), nil
}

// noEvidenceNudge is the one retry the minimum-evidence gate spends. It names
// the tools, because a model that skipped them may not have registered they
// exist, and it re-states the bar rather than the format — the verdict it just
// produced was well-formed, only unearned.
const noEvidenceNudge = "You reached a verdict without reading any code: no read_file or grep_repo call was made. " +
	"The snippet and taint trace in the prompt are the scanner's claim, not verification of it. " +
	"Open the flagged region with read_file, follow the input with read_file/grep_repo, then reply with the verdict JSON."

func noEvidenceReason(failed int) string {
	if failed > 0 {
		return fmt.Sprintf("verdict reached with no code read: all %d tool calls were rejected, and the model repeated the verdict when asked to gather evidence", failed)
	}
	return "verdict reached with no code read: the model made no read_file or grep_repo call, and repeated the verdict when asked to gather evidence"
}

// FlaggedRegion is the region the finding points at, used for codeHash.
func FlaggedRegion(f sarif.Finding) cache.Region {
	return cache.Region{File: f.File, Start: f.StartLine, End: f.EndLine}
}

// ShortCircuit handles findings decidable by pure rule, without the LLM:
// code in test or fixture paths is not production attack surface.
func ShortCircuit(f sarif.Finding) (Verdict, bool) {
	if !isTestPath(f.File) {
		return Verdict{}, false
	}
	return Verdict{
		Verdict:      VerdictBenign,
		Reason:       fmt.Sprintf("flagged code is in test/fixture path %s, which is not part of the production attack surface", f.File),
		Evidence:     []string{FlaggedRegion(f).Ref()},
		ShortCircuit: true,
	}, true
}

func isTestPath(file string) bool {
	if strings.Contains(path.Base(file), "_test.") {
		return true
	}
	for _, seg := range strings.Split(path.Dir(file), "/") {
		switch seg {
		case "testdata", "test", "tests", "__tests__", "fixtures":
			return true
		}
	}
	return false
}

// isContextFree reports rules whose evidence is the snippet itself, e.g.
// hardcoded credentials — no data flow to trace.
func isContextFree(f sarif.Finding) bool {
	probe := strings.ToLower(f.RuleID + " " + strings.Join(f.Tags, " "))
	for _, kw := range []string{"hardcoded", "hard-coded", "secret", "credential"} {
		if strings.Contains(probe, kw) {
			return true
		}
	}
	return false
}

// validate enforces the asymmetric evidence bar. benign with missing or
// unverifiable evidence downgrades to uncertain; exploitable and uncertain
// merely have unverifiable refs dropped (they must not poison the codeHash).
func (t *Triager) validate(v Verdict, f sarif.Finding) Verdict {
	switch v.Verdict {
	case VerdictBenign, VerdictExploitable, VerdictUncertain:
	default:
		return t.uncertain(f, v.Tokens, v.ToolCalls, fmt.Sprintf("model returned unknown verdict %q", v.Verdict))
	}

	var valid, invalid []string
	for _, ref := range v.Evidence {
		if t.checkRef(ref) {
			valid = append(valid, ref)
		} else {
			invalid = append(invalid, ref)
		}
	}

	if v.Verdict == VerdictBenign {
		if len(invalid) > 0 {
			return t.uncertain(f, v.Tokens, v.ToolCalls, fmt.Sprintf("benign verdict cited unverifiable evidence %v — evidence bar not met", invalid))
		}
		if len(valid) == 0 {
			return t.uncertain(f, v.Tokens, v.ToolCalls, "benign verdict cited no evidence — evidence bar not met")
		}
	}
	v.Evidence = valid
	return v
}

// checkRef verifies an evidence ref parses and points at readable lines
// inside the repo.
func (t *Triager) checkRef(ref string) bool {
	r, err := cache.ParseRef(ref)
	if err != nil {
		return false
	}
	_, err = cache.CodeHash(t.root, r, nil)
	return err == nil
}

func (t *Triager) uncertain(f sarif.Finding, tokens Tokens, toolCalls int, reason string) Verdict {
	return Verdict{
		Verdict:   VerdictUncertain,
		Reason:    reason,
		Tokens:    tokens,
		ToolCalls: toolCalls,
	}
}

func toolCalls(resp *Response) []Block {
	var calls []Block
	for _, b := range resp.Content {
		if b.Type == "tool_use" {
			calls = append(calls, b)
		}
	}
	return calls
}

func responseText(resp *Response) string {
	var parts []string
	for _, b := range resp.Content {
		if b.Type == "text" {
			parts = append(parts, b.Text)
		}
	}
	return strings.Join(parts, "\n")
}

// parseVerdict extracts the verdict JSON object from model text, tolerating
// code fences and surrounding prose.
func parseVerdict(text string) (Verdict, error) {
	start := strings.Index(text, "{")
	end := strings.LastIndex(text, "}")
	if start < 0 || end <= start {
		return Verdict{}, fmt.Errorf("no JSON object in response")
	}
	var v Verdict
	if err := json.Unmarshal([]byte(text[start:end+1]), &v); err != nil {
		return Verdict{}, fmt.Errorf("parse verdict: %w", err)
	}
	if v.Verdict == "" {
		return Verdict{}, fmt.Errorf("verdict JSON missing \"verdict\" field")
	}
	return v, nil
}
