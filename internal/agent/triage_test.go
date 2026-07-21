package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/alexpermiakov/sast-triage/internal/sarif"
)

const sampleRoot = "../../testdata/sampleapp"

// fakeClient replays a scripted sequence of responses and records every
// request so tests can assert on the transcript.
type fakeClient struct {
	mu        sync.Mutex
	responses []*Response
	requests  []Request
}

func (c *fakeClient) Complete(_ context.Context, req Request) (*Response, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.requests = append(c.requests, req)
	if len(c.responses) == 0 {
		return nil, fmt.Errorf("fake client: script exhausted after %d calls", len(c.requests))
	}
	resp := c.responses[0]
	c.responses = c.responses[1:]
	return resp, nil
}

func textResp(text string) *Response {
	return &Response{
		Content:      []Block{{Type: "text", Text: text}},
		StopReason:   "end_turn",
		InputTokens:  100,
		OutputTokens: 50,
	}
}

func toolUseResp(id, name string, args map[string]any) *Response {
	raw, _ := json.Marshal(args)
	return &Response{
		Content:      []Block{{Type: "tool_use", ID: id, Name: name, Input: raw}},
		StopReason:   "tool_use",
		InputTokens:  100,
		OutputTokens: 50,
	}
}

// sqliFinding is the fixture's SQL injection finding in app/handlers.go:17
// with a 3-hop taint trace.
func sqliFinding(t *testing.T) sarif.Finding {
	t.Helper()
	findings, err := sarif.ParseFile("../../testdata/findings.sarif")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.File == "app/handlers.go" {
			return f
		}
	}
	t.Fatal("fixture missing app/handlers.go finding")
	return sarif.Finding{}
}

func newTriager(t *testing.T, client Client, cfg Config) *Triager {
	t.Helper()
	if cfg.Model == "" {
		cfg.Model = "test-model"
	}
	tr, err := New(client, sampleRoot, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return tr
}

func TestOneTurnResolve(t *testing.T) {
	client := &fakeClient{responses: []*Response{
		textResp(`{"verdict": "exploitable", "reason": "id flows unsanitized from query param to QueryRow", "evidence": ["app/handlers.go:16", "app/handlers.go:17-18"]}`),
	}}
	v, err := newTriager(t, client, Config{}).TriageFinding(context.Background(), sqliFinding(t))
	if err != nil {
		t.Fatal(err)
	}
	if v.Verdict != VerdictExploitable {
		t.Errorf("verdict = %s, want exploitable", v.Verdict)
	}
	if len(v.Evidence) != 2 {
		t.Errorf("evidence = %v, want both refs kept", v.Evidence)
	}
	if v.Tokens.Total() != 150 {
		t.Errorf("tokens = %+v, want 150 total", v.Tokens)
	}
	// The split is what the summary footer reports; a total that is right
	// while the halves are swapped would go unnoticed without this.
	if v.Tokens.In != 100 || v.Tokens.Out != 50 {
		t.Errorf("tokens = %+v, want In:100 Out:50", v.Tokens)
	}
	// The first prompt must carry the trace as the starting map.
	prompt := client.requests[0].Messages[0].Content[0].Text
	for _, want := range []string{"app/handlers.go:17", "Taint trace", "verify each hop"} {
		if !strings.Contains(prompt, want) {
			t.Errorf("first prompt missing %q", want)
		}
	}
}

func TestMultiTurnTraceFollowing(t *testing.T) {
	client := &fakeClient{responses: []*Response{
		toolUseResp("t1", "read_file", map[string]any{"path": "app/handlers.go", "start_line": 10}),
		textResp(`{"verdict": "benign", "reason": "test claim", "evidence": ["app/handlers.go:16"]}`),
	}}
	v, err := newTriager(t, client, Config{}).TriageFinding(context.Background(), sqliFinding(t))
	if err != nil {
		t.Fatal(err)
	}
	if v.Verdict != VerdictBenign {
		t.Fatalf("verdict = %s, want benign (evidence was valid)", v.Verdict)
	}

	if len(client.requests) != 2 {
		t.Fatalf("got %d calls, want 2", len(client.requests))
	}
	second := client.requests[1].Messages
	last := second[len(second)-1]
	if last.Role != "user" || last.Content[0].Type != "tool_result" || last.Content[0].ToolUseID != "t1" {
		t.Fatalf("second call must carry the tool_result, got %+v", last)
	}
	if !strings.Contains(last.Content[0].Text, "17: \tquery := fmt.Sprintf") {
		t.Errorf("tool_result missing numbered file content:\n%s", last.Content[0].Text)
	}
	if last.Content[0].IsError {
		t.Error("valid read_file must not be an error result")
	}
}

func TestIterationCapExhaustion(t *testing.T) {
	client := &fakeClient{responses: []*Response{
		toolUseResp("t1", "read_file", map[string]any{"path": "app/handlers.go"}),
		toolUseResp("t2", "read_file", map[string]any{"path": "app/db.go"}),
		toolUseResp("t3", "grep_repo", map[string]any{"pattern": "QueryRow"}),
	}}
	v, err := newTriager(t, client, Config{MaxIterations: 3}).TriageFinding(context.Background(), sqliFinding(t))
	if err != nil {
		t.Fatal(err)
	}
	if v.Verdict != VerdictUncertain {
		t.Errorf("verdict = %s, want uncertain on cap exhaustion", v.Verdict)
	}
	if !strings.Contains(v.Reason, "iteration cap") {
		t.Errorf("reason = %q", v.Reason)
	}
	if len(client.requests) != 3 {
		t.Errorf("made %d calls, cap was 3", len(client.requests))
	}
}

func TestMalformedVerdictRetryThenUncertain(t *testing.T) {
	client := &fakeClient{responses: []*Response{
		textResp("I believe this is fine because of reasons."),
		textResp("Still prose, still no JSON."),
	}}
	v, err := newTriager(t, client, Config{}).TriageFinding(context.Background(), sqliFinding(t))
	if err != nil {
		t.Fatal(err)
	}
	if v.Verdict != VerdictUncertain {
		t.Errorf("verdict = %s, want uncertain after failed retry", v.Verdict)
	}
	if len(client.requests) != 2 {
		t.Fatalf("got %d calls, want exactly one retry", len(client.requests))
	}
	retryMsgs := client.requests[1].Messages
	if !strings.Contains(retryMsgs[len(retryMsgs)-1].Content[0].Text, "ONLY the JSON object") {
		t.Error("retry turn must restate the required format")
	}
}

func TestMalformedVerdictRetryThenValid(t *testing.T) {
	client := &fakeClient{responses: []*Response{
		textResp("Verdict: exploitable, trust me."),
		textResp("```json" + "\n" + `{"verdict": "exploitable", "reason": "unsanitized flow", "evidence": ["app/handlers.go:16"]}` + "\n" + "```"),
	}}
	v, err := newTriager(t, client, Config{}).TriageFinding(context.Background(), sqliFinding(t))
	if err != nil {
		t.Fatal(err)
	}
	if v.Verdict != VerdictExploitable {
		t.Errorf("verdict = %s, want exploitable after successful retry (fenced JSON must parse)", v.Verdict)
	}
}

func TestPathTraversalToolCallRejectedLoopContinues(t *testing.T) {
	client := &fakeClient{responses: []*Response{
		toolUseResp("t1", "read_file", map[string]any{"path": "../../go.mod"}),
		textResp(`{"verdict": "uncertain", "reason": "could not verify", "evidence": []}`),
	}}
	v, err := newTriager(t, client, Config{}).TriageFinding(context.Background(), sqliFinding(t))
	if err != nil {
		t.Fatal(err)
	}
	if v.Verdict != VerdictUncertain {
		t.Errorf("verdict = %s, want uncertain", v.Verdict)
	}
	second := client.requests[1].Messages
	result := second[len(second)-1].Content[0]
	if !result.IsError {
		t.Fatal("traversal tool call must come back as an is_error tool_result")
	}
	if !strings.Contains(result.Text, "escapes repo root") {
		t.Errorf("rejection reason: %q", result.Text)
	}
}

func TestBenignWithoutEvidenceFailsClosed(t *testing.T) {
	tests := map[string]string{
		"no evidence":           `{"verdict": "benign", "reason": "looks fine", "evidence": []}`,
		"unverifiable evidence": `{"verdict": "benign", "reason": "sanitized", "evidence": ["app/handlers.go:9999"]}`,
		"nonexistent file":      `{"verdict": "benign", "reason": "sanitized", "evidence": ["app/sanitizer.go:10"]}`,
		"unknown verdict":       `{"verdict": "safe", "reason": "x", "evidence": ["app/handlers.go:16"]}`,
	}
	for name, reply := range tests {
		t.Run(name, func(t *testing.T) {
			client := &fakeClient{responses: []*Response{textResp(reply)}}
			v, err := newTriager(t, client, Config{}).TriageFinding(context.Background(), sqliFinding(t))
			if err != nil {
				t.Fatal(err)
			}
			if v.Verdict != VerdictUncertain {
				t.Errorf("verdict = %s, want uncertain (never default to benign)", v.Verdict)
			}
		})
	}
}

func TestTokenBudgetExhaustion(t *testing.T) {
	client := &fakeClient{responses: []*Response{
		toolUseResp("t1", "read_file", map[string]any{"path": "app/handlers.go"}),
	}}
	v, err := newTriager(t, client, Config{TokenBudget: 100}).TriageFinding(context.Background(), sqliFinding(t))
	if err != nil {
		t.Fatal(err)
	}
	if v.Verdict != VerdictUncertain || !strings.Contains(v.Reason, "token budget") {
		t.Errorf("got %s (%q), want uncertain on token budget", v.Verdict, v.Reason)
	}
	if len(client.requests) != 1 {
		t.Errorf("made %d calls after budget blown, want 1", len(client.requests))
	}
}

// TestTokenBudgetStopsBeforeOvershoot pins the predictive stop: every
// continuation re-sends the whole conversation, so once a repeat of the last
// call cannot fit in the budget the loop must stop — while still under budget,
// not one giant call past it.
func TestTokenBudgetStopsBeforeOvershoot(t *testing.T) {
	grow := toolUseResp("t1", "read_file", map[string]any{"path": "app/handlers.go"})
	grow.InputTokens = 6000 // conversation already large: a repeat blows the 10k budget
	client := &fakeClient{responses: []*Response{grow}}
	v, err := newTriager(t, client, Config{TokenBudget: 10000}).TriageFinding(context.Background(), sqliFinding(t))
	if err != nil {
		t.Fatal(err)
	}
	if v.Verdict != VerdictUncertain || !strings.Contains(v.Reason, "token budget") {
		t.Errorf("got %s (%q), want uncertain on token budget", v.Verdict, v.Reason)
	}
	if len(client.requests) != 1 {
		t.Errorf("made %d calls, want 1: the loop must not issue a call that cannot fit", len(client.requests))
	}
	if v.Tokens.Total() > 10000 {
		t.Errorf("tokens = %d exceeds the 10k budget — predictive stop failed", v.Tokens.Total())
	}
}

func TestTestFileShortCircuit(t *testing.T) {
	findings, err := sarif.ParseFile("../../testdata/findings.sarif")
	if err != nil {
		t.Fatal(err)
	}
	var testFinding sarif.Finding
	for _, f := range findings {
		if f.File == "app/handlers_test.go" {
			testFinding = f
		}
	}
	client := &fakeClient{} // no scripted responses: any call fails the test
	v, err := newTriager(t, client, Config{}).TriageFinding(context.Background(), testFinding)
	if err != nil {
		t.Fatal(err)
	}
	if v.Verdict != VerdictBenign || !v.ShortCircuit {
		t.Errorf("got %+v, want short-circuit benign", v)
	}
	if len(v.Evidence) != 1 || v.Evidence[0] != "app/handlers_test.go:7" {
		t.Errorf("evidence = %v, want the flagged region itself", v.Evidence)
	}
	if len(client.requests) != 0 {
		t.Errorf("short circuit must not call the LLM, made %d calls", len(client.requests))
	}
}

func TestContextFreeRuleSingleCallNoTools(t *testing.T) {
	findings, err := sarif.ParseFile("../../testdata/findings.sarif")
	if err != nil {
		t.Fatal(err)
	}
	var secret sarif.Finding
	for _, f := range findings {
		if f.File == "app/config.go" {
			secret = f
		}
	}
	if !isContextFree(secret) {
		t.Fatal("hardcoded-password finding should be context-free")
	}
	client := &fakeClient{responses: []*Response{
		textResp(`{"verdict": "exploitable", "reason": "production password committed to source", "evidence": ["app/config.go:7"]}`),
	}}
	v, err := newTriager(t, client, Config{}).TriageFinding(context.Background(), secret)
	if err != nil {
		t.Fatal(err)
	}
	if v.Verdict != VerdictExploitable {
		t.Errorf("verdict = %s", v.Verdict)
	}
	if len(client.requests) != 1 {
		t.Fatalf("context-free tier made %d calls, want 1", len(client.requests))
	}
	if len(client.requests[0].Tools) != 0 {
		t.Error("context-free tier must not offer tools")
	}
}

func TestTransportErrorPropagates(t *testing.T) {
	client := &fakeClient{} // empty script → Complete returns an error
	_, err := newTriager(t, client, Config{}).TriageFinding(context.Background(), sqliFinding(t))
	if err == nil {
		t.Fatal("transport errors must propagate (caller reports uncertain but must not cache)")
	}
}
