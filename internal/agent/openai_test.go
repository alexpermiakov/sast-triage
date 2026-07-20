package agent

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
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

	c := NewOpenAIClient(srv.URL, "k", 4)
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

	c := NewOpenAIClient(srv.URL, "", 4)
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

// --- retry policy ---

const okChatResponse = `{
	"choices": [{"finish_reason": "stop", "message": {"role": "assistant", "content": "done"}}],
	"usage": {"prompt_tokens": 1, "completion_tokens": 2}
}`

func probeRequest() Request {
	return Request{Model: "m", MaxTokens: 16, Messages: []Message{
		{Role: "user", Content: []Block{{Type: "text", Text: "hi"}}},
	}}
}

// retryClient returns a client whose backoff is recorded instead of waited on,
// so retry policy is asserted without real sleeping.
func retryClient(t *testing.T, url string) (*OpenAIClient, *[]time.Duration) {
	t.Helper()
	c := NewOpenAIClient(url, "", 4)
	c.baseDelay = time.Second
	c.maxDelay = 8 * time.Second
	delays := &[]time.Duration{}
	c.sleep = func(_ context.Context, d time.Duration) error {
		*delays = append(*delays, d)
		return nil
	}
	return c, delays
}

// flakyServer fails the first n requests with the given status, then succeeds.
func flakyServer(t *testing.T, n int, status int, hdr map[string]string) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if int(attempts.Add(1)) <= n {
			for k, v := range hdr {
				w.Header().Set(k, v)
			}
			w.WriteHeader(status)
			io.WriteString(w, `{"error":{"message":"transient"}}`)
			return
		}
		io.WriteString(w, okChatResponse)
	}))
	t.Cleanup(srv.Close)
	return srv, &attempts
}

func TestOpenAIRetriesTransientFailures(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
	}{
		{"rate limited", http.StatusTooManyRequests},
		{"service unavailable", http.StatusServiceUnavailable},
		{"bad gateway", http.StatusBadGateway},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, attempts := flakyServer(t, 2, tc.status, nil)
			c, delays := retryClient(t, srv.URL)

			resp, err := c.Complete(context.Background(), probeRequest())
			if err != nil {
				t.Fatalf("Complete: %v", err)
			}
			if responseText(resp) != "done" {
				t.Errorf("response not surfaced after retry: %q", responseText(resp))
			}
			if got := attempts.Load(); got != 3 {
				t.Errorf("attempts = %d, want 3 (two failures then success)", got)
			}
			// Exponential with jitter: each delay in [d/2, d] for d = 1s, 2s.
			if len(*delays) != 2 {
				t.Fatalf("delays = %v, want 2", *delays)
			}
			for i, d := range *delays {
				lo := time.Duration(1<<i) * time.Second / 2
				hi := time.Duration(1<<i) * time.Second
				if d < lo || d > hi {
					t.Errorf("delay[%d] = %v, want within [%v, %v]", i, d, lo, hi)
				}
			}
		})
	}
}

func TestOpenAIHonorsRetryAfterHeader(t *testing.T) {
	srv, _ := flakyServer(t, 1, http.StatusTooManyRequests, map[string]string{"Retry-After": "5"})
	c, delays := retryClient(t, srv.URL)

	if _, err := c.Complete(context.Background(), probeRequest()); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	// The server's number wins over our jittered guess (which would be <= 1s).
	if len(*delays) != 1 || (*delays)[0] != 5*time.Second {
		t.Errorf("delays = %v, want [5s] from Retry-After", *delays)
	}
}

func TestOpenAIGivesUpAfterMaxRetries(t *testing.T) {
	srv, attempts := flakyServer(t, 100, http.StatusTooManyRequests, nil)
	c, _ := retryClient(t, srv.URL)

	_, err := c.Complete(context.Background(), probeRequest())
	if err == nil {
		t.Fatal("Complete succeeded against an endlessly rate-limited endpoint")
	}
	if !strings.Contains(err.Error(), "gave up after 4 attempts") {
		t.Errorf("error should report the bounded attempts, got: %v", err)
	}
	if got := attempts.Load(); got != 4 {
		t.Errorf("attempts = %d, want 4 (maxRetries 3 + 1)", got)
	}
}

func TestOpenAIDoesNotRetryClientErrors(t *testing.T) {
	// 401 will fail identically forever; burning the budget on it is waste.
	srv, attempts := flakyServer(t, 100, http.StatusUnauthorized, nil)
	c, delays := retryClient(t, srv.URL)

	if _, err := c.Complete(context.Background(), probeRequest()); err == nil {
		t.Fatal("Complete succeeded on 401")
	}
	if got := attempts.Load(); got != 1 {
		t.Errorf("attempts = %d, want 1 (no retry on 4xx)", got)
	}
	if len(*delays) != 0 {
		t.Errorf("slept %v before failing a non-transient error", *delays)
	}
}

func TestOpenAIStopsRetryingOnCancelledContext(t *testing.T) {
	srv, attempts := flakyServer(t, 100, http.StatusTooManyRequests, nil)
	c := NewOpenAIClient(srv.URL, "", 4)
	c.baseDelay, c.maxDelay = time.Millisecond, time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	c.sleep = func(ctx context.Context, d time.Duration) error {
		cancel() // the run shuts down mid-backoff
		return sleepCtx(ctx, d)
	}
	if _, err := c.Complete(ctx, probeRequest()); err == nil {
		t.Fatal("Complete succeeded despite cancellation")
	}
	if got := attempts.Load(); got != 1 {
		t.Errorf("attempts = %d, want 1: a cancelled ctx must not be retried into", got)
	}
}

func TestRetryAfter(t *testing.T) {
	const limit = 60 * time.Second
	for _, tc := range []struct {
		name  string
		value string
		want  time.Duration
		ok    bool
	}{
		{"absent", "", 0, false},
		{"seconds", "12", 12 * time.Second, true},
		{"zero", "0", 0, true},
		{"clamped to limit", "9999", limit, true},
		{"negative floored", "-5", 0, true},
		{"garbage ignored", "soon", 0, false},
		{"past http-date", "Mon, 02 Jan 2006 15:04:05 GMT", 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := http.Header{}
			if tc.value != "" {
				h.Set("Retry-After", tc.value)
			}
			got, ok := retryAfter(h, limit)
			if ok != tc.ok || got != tc.want {
				t.Errorf("retryAfter(%q) = (%v, %v), want (%v, %v)", tc.value, got, ok, tc.want, tc.ok)
			}
		})
	}
}

func TestOpenAIPoolSizedToParallel(t *testing.T) {
	// The default transport caps idle conns per host at 2, which would force a
	// fresh handshake for most requests of a parallel multi-turn run.
	c := NewOpenAIClient("http://x", "", 64)
	tr, ok := c.http.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport = %T, want *http.Transport", c.http.Transport)
	}
	if tr.MaxIdleConnsPerHost != 64 {
		t.Errorf("MaxIdleConnsPerHost = %d, want 64", tr.MaxIdleConnsPerHost)
	}
	if same := NewOpenAIClient("http://x", "", 0); same.http.Transport.(*http.Transport).MaxIdleConnsPerHost != 1 {
		t.Error("non-positive parallel must clamp to 1, not 0")
	}
}
