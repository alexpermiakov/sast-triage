package agent

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// captures the last request body the fake server received.
type capturedRequest struct {
	Model     string       `json:"model"`
	MaxTokens int          `json:"max_tokens"`
	Messages  []oaiMessage `json:"messages"`
	Tools     []oaiTool    `json:"tools"`
	Choice    string       `json:"tool_choice"`
}

func TestOpenAIToolCallRoundTrip(t *testing.T) {
	var got capturedRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer k" {
			t.Errorf("missing/incorrect auth header: %q", r.Header.Get("Authorization"))
		}
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &got); err != nil {
			t.Fatalf("server could not decode request: %v", err)
		}
		// Reply with a tool call whose arguments are a JSON-encoded string
		// (OpenAI's documented shape).
		io.WriteString(w, `{
			"choices": [{"finish_reason": "tool_calls", "message": {
				"role": "assistant",
				"content": "",
				"tool_calls": [{"id": "call_1", "type": "function",
					"function": {"name": "read_file", "arguments": "{\"path\":\"a.go\"}"}}]
			}}],
			"usage": {"prompt_tokens": 11, "completion_tokens": 7}
		}`)
	}))
	defer srv.Close()

	c := NewOpenAIClient(srv.URL, "k")
	resp, err := c.Complete(context.Background(), Request{
		Model:     "qwen2.5-coder:7b",
		System:    "sys",
		MaxTokens: 4096,
		Tools:     []ToolDef{{Name: "read_file", Description: "read", Properties: map[string]any{"path": map[string]any{"type": "string"}}, Required: []string{"path"}}},
		Messages: []Message{
			{Role: "user", Content: []Block{{Type: "text", Text: "triage this"}}},
		},
	})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}

	// Request mapping: system hoisted, tools + auto choice present.
	if got.Model != "qwen2.5-coder:7b" || got.MaxTokens != 4096 {
		t.Errorf("model/max_tokens not mapped: %+v", got)
	}
	if len(got.Messages) != 2 || got.Messages[0].Role != "system" || got.Messages[1].Role != "user" {
		t.Fatalf("messages not mapped: %+v", got.Messages)
	}
	if len(got.Tools) != 1 || got.Tools[0].Function.Name != "read_file" || got.Choice != "auto" {
		t.Errorf("tools/tool_choice not mapped: %+v choice=%q", got.Tools, got.Choice)
	}

	// Response mapping: tool_calls -> tool_use block with raw-JSON input.
	calls := toolCalls(resp)
	if len(calls) != 1 || calls[0].Name != "read_file" || calls[0].ID != "call_1" {
		t.Fatalf("tool_use not surfaced: %+v", resp.Content)
	}
	var args struct {
		Path string `json:"path"`
	}
	if err := json.Unmarshal(calls[0].Input, &args); err != nil || args.Path != "a.go" {
		t.Errorf("tool args not normalized to raw JSON: %s (%v)", calls[0].Input, err)
	}
	if resp.StopReason != "tool_use" {
		t.Errorf("finish_reason not mapped: %q", resp.StopReason)
	}
	if resp.InputTokens != 11 || resp.OutputTokens != 7 {
		t.Errorf("usage not mapped: in=%d out=%d", resp.InputTokens, resp.OutputTokens)
	}
}

// A user turn carrying tool_result blocks must become standalone role:"tool"
// messages keyed by tool_call_id — OpenAI's shape, not Anthropic's.
func TestOpenAIToolResultBecomesToolRole(t *testing.T) {
	var got capturedRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &got)
		io.WriteString(w, `{"choices":[{"finish_reason":"stop","message":{"role":"assistant","content":"{\"verdict\":\"benign\"}"}}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`)
	}))
	defer srv.Close()

	c := NewOpenAIClient(srv.URL, "")
	rawArgs := json.RawMessage(`{"path":"a.go"}`)
	resp, err := c.Complete(context.Background(), Request{
		Model: "m",
		Messages: []Message{
			{Role: "user", Content: []Block{{Type: "text", Text: "go"}}},
			{Role: "assistant", Content: []Block{{Type: "tool_use", ID: "call_1", Name: "read_file", Input: rawArgs}}},
			{Role: "user", Content: []Block{{Type: "tool_result", ToolUseID: "call_1", Text: "file contents"}}},
		},
	})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}

	// Expect: user, assistant(with tool_calls), tool.
	if len(got.Messages) != 3 {
		t.Fatalf("want 3 messages, got %d: %+v", len(got.Messages), got.Messages)
	}
	asst := got.Messages[1]
	if asst.Role != "assistant" || len(asst.ToolCalls) != 1 || asst.ToolCalls[0].ID != "call_1" {
		t.Errorf("assistant tool_calls not mapped: %+v", asst)
	}
	// Arguments must be a JSON-encoded string on the wire.
	var argsStr string
	if err := json.Unmarshal(asst.ToolCalls[0].Function.Arguments, &argsStr); err != nil {
		t.Errorf("arguments not sent as a JSON string: %s", asst.ToolCalls[0].Function.Arguments)
	} else if argsStr != `{"path":"a.go"}` {
		t.Errorf("arguments string wrong: %q", argsStr)
	}
	toolMsg := got.Messages[2]
	if toolMsg.Role != "tool" || toolMsg.ToolCallID != "call_1" || toolMsg.Content != "file contents" {
		t.Errorf("tool_result not mapped to role:tool: %+v", toolMsg)
	}

	if txt := responseText(resp); txt != `{"verdict":"benign"}` {
		t.Errorf("response text not surfaced: %q", txt)
	}
}
