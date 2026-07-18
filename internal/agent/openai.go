package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// OpenAIClient is a Client backed by any OpenAI-compatible chat-completions
// endpoint: OpenAI itself, or a local/self-hosted server such as Ollama, vLLM,
// or LM Studio. It uses only net/http — no provider SDK — and talks solely to
// the configured base URL, so data goes to a hosted service only if you point
// it at one. This is the default provider precisely so the out-of-the-box path
// keeps code on the user's own machine.
type OpenAIClient struct {
	baseURL string
	apiKey  string
	http    *http.Client
}

// NewOpenAIClient targets baseURL (e.g. http://localhost:11434/v1 for Ollama).
// apiKey may be empty: local endpoints ignore it; hosted ones need it. When
// set, it is sent only as a Bearer token to baseURL.
func NewOpenAIClient(baseURL, apiKey string) *OpenAIClient {
	return &OpenAIClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		apiKey:  apiKey,
		// Generous ceiling for slow local models; the caller's ctx still cancels.
		http: &http.Client{Timeout: 5 * time.Minute},
	}
}

func (c *OpenAIClient) Complete(ctx context.Context, req Request) (*Response, error) {
	body := oaiRequest{
		Model:     req.Model,
		MaxTokens: req.MaxTokens,
		Messages:  toOpenAIMessages(req),
	}
	for _, t := range req.Tools {
		params := map[string]any{"type": "object", "properties": t.Properties}
		if len(t.Required) > 0 {
			params["required"] = t.Required
		}
		body.Tools = append(body.Tools, oaiTool{
			Type:     "function",
			Function: oaiFunction{Name: t.Name, Description: t.Description, Parameters: params},
		})
	}
	if len(body.Tools) > 0 {
		body.ToolChoice = "auto"
	}

	buf, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("openai marshal request: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/chat/completions", bytes.NewReader(buf))
	if err != nil {
		return nil, fmt.Errorf("openai build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	res, err := c.http.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("openai chat.completions: %w", err)
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("openai read response: %w", err)
	}
	if res.StatusCode/100 != 2 {
		return nil, fmt.Errorf("openai chat.completions: %s: %s", res.Status, snippet(raw))
	}

	var out oaiResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("openai decode response: %w", err)
	}
	if out.Error != nil && out.Error.Message != "" {
		return nil, fmt.Errorf("openai chat.completions: %s", out.Error.Message)
	}
	if len(out.Choices) == 0 {
		return nil, fmt.Errorf("openai chat.completions: response had no choices")
	}

	msg := out.Choices[0].Message
	resp := &Response{
		StopReason:   mapFinishReason(out.Choices[0].FinishReason),
		InputTokens:  out.Usage.PromptTokens,
		OutputTokens: out.Usage.CompletionTokens,
	}
	if msg.Content != "" {
		resp.Content = append(resp.Content, Block{Type: "text", Text: msg.Content})
	}
	for _, tc := range msg.ToolCalls {
		resp.Content = append(resp.Content, Block{
			Type:  "tool_use",
			ID:    tc.ID,
			Name:  tc.Function.Name,
			Input: normalizeToolArgs(tc.Function.Arguments),
		})
	}
	return resp, nil
}

// toOpenAIMessages flattens the internal Message list into OpenAI wire format:
// the system prompt becomes a leading system message; tool_use blocks become
// assistant tool_calls; tool_result blocks become their own role:"tool"
// messages (OpenAI's shape), keyed by tool_call_id.
func toOpenAIMessages(req Request) []oaiMessage {
	var out []oaiMessage
	if req.System != "" {
		out = append(out, oaiMessage{Role: "system", Content: req.System})
	}
	for _, m := range req.Messages {
		var text []string
		var calls []oaiToolCall
		var results []oaiMessage
		for _, b := range m.Content {
			switch b.Type {
			case "text":
				text = append(text, b.Text)
			case "tool_use":
				in := b.Input
				if len(in) == 0 {
					in = json.RawMessage("{}")
				}
				// OpenAI arguments is a JSON-encoded *string*, so encode the
				// object text as a string literal ({"a":1} -> "{\"a\":1}").
				argStr, err := json.Marshal(string(in))
				if err != nil {
					argStr = []byte(`"{}"`)
				}
				tc := oaiToolCall{ID: b.ID, Type: "function"}
				tc.Function.Name = b.Name
				tc.Function.Arguments = json.RawMessage(argStr)
				calls = append(calls, tc)
			case "tool_result":
				results = append(results, oaiMessage{Role: "tool", ToolCallID: b.ToolUseID, Content: b.Text})
			}
		}
		// In this agent a user turn is either all text or all tool_results,
		// never mixed; results become standalone tool messages.
		if len(results) > 0 {
			out = append(out, results...)
			continue
		}
		out = append(out, oaiMessage{Role: m.Role, Content: strings.Join(text, "\n"), ToolCalls: calls})
	}
	return out
}

// normalizeToolArgs returns the tool arguments as raw JSON. OpenAI specifies
// arguments as a JSON-encoded string, but some compatible servers (Ollama has,
// across versions) return a bare object; accept both.
func normalizeToolArgs(raw json.RawMessage) json.RawMessage {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return json.RawMessage("{}")
	}
	if raw[0] == '"' {
		var s string
		if err := json.Unmarshal(raw, &s); err == nil {
			if strings.TrimSpace(s) == "" {
				return json.RawMessage("{}")
			}
			return json.RawMessage(s)
		}
	}
	return raw
}

func mapFinishReason(fr string) string {
	switch fr {
	case "tool_calls":
		return "tool_use"
	case "length":
		return "max_tokens"
	case "stop":
		return "end_turn"
	default:
		return fr
	}
}

func snippet(b []byte) string {
	const max = 300
	s := strings.TrimSpace(string(b))
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}

// --- OpenAI chat-completions wire subset ---

type oaiRequest struct {
	Model      string       `json:"model"`
	Messages   []oaiMessage `json:"messages"`
	Tools      []oaiTool    `json:"tools,omitempty"`
	ToolChoice string       `json:"tool_choice,omitempty"`
	MaxTokens  int          `json:"max_tokens,omitempty"`
}

type oaiMessage struct {
	Role       string        `json:"role"`
	Content    string        `json:"content"`
	ToolCalls  []oaiToolCall `json:"tool_calls,omitempty"`
	ToolCallID string        `json:"tool_call_id,omitempty"`
}

type oaiTool struct {
	Type     string      `json:"type"`
	Function oaiFunction `json:"function"`
}

type oaiFunction struct {
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	Parameters  map[string]any `json:"parameters"`
}

// oaiToolCall serves both directions: on the request its Arguments is the JSON
// string we send; on the response it is decoded via normalizeToolArgs.
type oaiToolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type,omitempty"`
	Function struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	} `json:"function"`
}

type oaiResponse struct {
	Choices []struct {
		FinishReason string     `json:"finish_reason"`
		Message      oaiMessage `json:"message"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
	} `json:"usage"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}
