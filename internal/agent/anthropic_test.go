package agent

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// A named -base-url must reach the wire. It used to be accepted and silently
// dropped, so `-provider anthropic -base-url https://gateway/` called
// api.anthropic.com instead — the one thing this tool promises never to do.
func TestAnthropicClientHonoursBaseURL(t *testing.T) {
	var gotPath, gotKey string
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		gotPath, gotKey = r.URL.Path, r.Header.Get("x-api-key")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","role":"assistant",
			"model":"claude-sonnet-5","content":[{"type":"text","text":"ok"}],
			"stop_reason":"end_turn","usage":{"input_tokens":3,"output_tokens":4}}`))
	}))
	defer srv.Close()

	c := NewAnthropicClient("test-key", srv.URL)
	resp, err := c.Complete(context.Background(), Request{
		Model:     "claude-sonnet-5",
		System:    "sys",
		Messages:  []Message{{Role: "user", Content: []Block{{Type: "text", Text: "hi"}}}},
		MaxTokens: 16,
	})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}

	if hits != 1 {
		t.Fatalf("base-url ignored: gateway got %d requests, want 1", hits)
	}
	if gotKey != "test-key" {
		t.Errorf("x-api-key = %q, want test-key", gotKey)
	}
	if gotPath != "/v1/messages" {
		t.Errorf("path = %q, want /v1/messages", gotPath)
	}
	if resp.StopReason != "end_turn" || resp.InputTokens != 3 || resp.OutputTokens != 4 {
		t.Errorf("response = %+v, want end_turn 3/4", resp)
	}
	if len(resp.Content) != 1 || resp.Content[0].Text != "ok" {
		t.Errorf("content = %+v, want one text block \"ok\"", resp.Content)
	}
}

// The project sends no sampling parameters on any provider, and the native API
// would reject them anyway: Opus 4.8/4.7, Sonnet 5 and Fable 5 answer
// temperature, top_p or top_k with a 400. This guards against a regression that
// reintroduces one on the Anthropic path.
func TestAnthropicClientNeverSendsTemperature(t *testing.T) {
	var body map[string]json.RawMessage
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read body: %v", err)
		}
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Errorf("unmarshal body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","role":"assistant",
			"model":"claude-opus-4-8","content":[{"type":"text","text":"ok"}],
			"stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}`))
	}))
	defer srv.Close()

	if _, err := NewAnthropicClient("k", srv.URL).Complete(context.Background(), Request{
		Model:     "claude-opus-4-8",
		System:    "sys",
		Messages:  []Message{{Role: "user", Content: []Block{{Type: "text", Text: "hi"}}}},
		MaxTokens: 16,
	}); err != nil {
		t.Fatalf("Complete: %v", err)
	}

	for _, key := range []string{"temperature", "top_p", "top_k"} {
		if _, ok := body[key]; ok {
			t.Errorf("request carried %q; the current Claude models reject it with a 400", key)
		}
	}
}

// Empty base URL keeps the SDK default rather than sending requests to "".
func TestAnthropicClientEmptyBaseURLUsesDefault(t *testing.T) {
	if c := NewAnthropicClient("k", ""); c == nil || c.client.Options == nil {
		t.Fatal("NewAnthropicClient with empty base URL produced no usable client")
	}
}
