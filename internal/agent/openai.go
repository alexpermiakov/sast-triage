package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"strconv"
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

	// Retry policy for transient failures, bounded by construction: at most
	// maxRetries+1 attempts, so a saturated endpoint slows a run down but can
	// never hang it. Fields are settable in-package for tests.
	maxRetries int
	baseDelay  time.Duration
	maxDelay   time.Duration
	sleep      func(context.Context, time.Duration) error
}

// NewOpenAIClient targets baseURL (e.g. http://localhost:11434/v1 for Ollama).
// apiKey may be empty: local endpoints ignore it; hosted ones need it. When
// set, it is sent only as a Bearer token to baseURL. parallel is the run's
// concurrency, used to size the connection pool.
func NewOpenAIClient(baseURL, apiKey string, parallel int) *OpenAIClient {
	if parallel < 1 {
		parallel = 1
	}
	// DefaultTransport keeps only 2 idle connections per host, so a run at
	// -parallel N would discard and re-handshake nearly every request of the
	// agent's multi-turn loop. Size the pool to the real concurrency: one
	// worker holds at most one connection to the single configured endpoint.
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.MaxIdleConnsPerHost = parallel
	tr.MaxIdleConns = parallel

	return &OpenAIClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		apiKey:  apiKey,
		// Generous ceiling for slow local models; the caller's ctx still cancels.
		http:       &http.Client{Timeout: 5 * time.Minute, Transport: tr},
		maxRetries: 3,
		baseDelay:  time.Second,
		maxDelay:   60 * time.Second,
		sleep:      sleepCtx,
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
	raw, err := c.post(ctx, buf)
	if err != nil {
		return nil, err
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

// oaiAttempt is the outcome of one HTTP round trip, kept whole so the retry
// loop can consult the status and Retry-After of the attempt it is judging.
type oaiAttempt struct {
	body   []byte
	code   int
	status string // "429 Too Many Requests"
	header http.Header
}

// post sends one chat-completions request, retrying transient failures — 429,
// 5xx, and transport errors including the client timeout firing on a saturated
// endpoint — with exponential backoff plus jitter, honoring a server-sent
// Retry-After. Attempts are hard-capped at maxRetries+1. This matters beyond
// latency: without it a rate-limited or queue-stalled request surfaces as an
// error, which the pipeline degrades to an *uncached* uncertain verdict, so the
// finding is paid for again on the next run.
func (c *OpenAIClient) post(ctx context.Context, buf []byte) ([]byte, error) {
	var lastErr error
	for attempt := 0; ; attempt++ {
		a, err := c.attempt(ctx, buf)
		switch {
		case err != nil:
			// A cancelled or expired caller ctx is a decision, not a fault:
			// the run is shutting down and must not retry into it.
			if ctx.Err() != nil {
				return nil, err
			}
			lastErr = err
		case a.code/100 == 2:
			return a.body, nil
		case retryableStatus(a.code):
			lastErr = fmt.Errorf("openai chat.completions: %s: %s", a.status, snippet(a.body))
		default:
			// 4xx other than 429: a request we built wrong and would build
			// wrong again. Fail now rather than burning the budget.
			return nil, fmt.Errorf("openai chat.completions: %s: %s", a.status, snippet(a.body))
		}

		if attempt >= c.maxRetries {
			return nil, fmt.Errorf("openai chat.completions: gave up after %d attempts: %w", attempt+1, lastErr)
		}
		delay := c.backoff(attempt)
		if d, ok := retryAfter(a.header, c.maxDelay); ok {
			delay = d // the server's own number beats our guess
		}
		if err := c.sleep(ctx, delay); err != nil {
			return nil, err
		}
	}
}

// attempt performs one round trip. The response body is always drained and
// closed, including on error statuses: an undrained body cannot return to the
// idle pool, which would defeat the pool sizing in the constructor.
func (c *OpenAIClient) attempt(ctx context.Context, buf []byte) (oaiAttempt, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/chat/completions", bytes.NewReader(buf))
	if err != nil {
		return oaiAttempt{}, fmt.Errorf("openai build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	res, err := c.http.Do(httpReq)
	if err != nil {
		return oaiAttempt{}, fmt.Errorf("openai chat.completions: %w", err)
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(res.Body)
	if err != nil {
		return oaiAttempt{}, fmt.Errorf("openai read response: %w", err)
	}
	return oaiAttempt{body: raw, code: res.StatusCode, status: res.Status, header: res.Header}, nil
}

// retryableStatus reports whether a status warrants another attempt: 429 (rate
// limited) and 5xx (overloaded, restarting, gateway hiccup) are transient.
func retryableStatus(code int) bool {
	return code == http.StatusTooManyRequests || code >= 500
}

// backoff returns the delay before the next attempt: exponential from
// baseDelay, clamped at maxDelay, with jitter so the parallel workers that
// tripped the same rate limit do not all retry in lockstep.
func (c *OpenAIClient) backoff(attempt int) time.Duration {
	d := c.baseDelay << attempt
	if d <= 0 || d > c.maxDelay { // <= 0 catches the shift overflowing
		d = c.maxDelay
	}
	half := d / 2
	return half + time.Duration(rand.Int64N(int64(half)+1))
}

// retryAfter reads a server-directed delay from the Retry-After header, which
// is either a count of seconds or an HTTP-date. The value is clamped to limit
// so a broken or hostile endpoint cannot stall the run.
func retryAfter(h http.Header, limit time.Duration) (time.Duration, bool) {
	v := strings.TrimSpace(h.Get("Retry-After"))
	if v == "" {
		return 0, false
	}
	var d time.Duration
	if secs, err := strconv.Atoi(v); err == nil {
		d = time.Duration(secs) * time.Second
	} else {
		t, err := http.ParseTime(v)
		if err != nil {
			return 0, false
		}
		d = time.Until(t) // a date already past yields <= 0: retry immediately
	}
	return min(max(d, 0), limit), true
}

// sleepCtx waits for d, or returns early if the caller's ctx ends first.
func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
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
