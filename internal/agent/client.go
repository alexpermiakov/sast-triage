// Package agent runs the bounded LLM triage loop. It is the only
// nondeterministic package in the binary; everything the loop does is capped
// (iterations, tokens, tool output) and every tool is read-only.
package agent

import (
	"context"
	"encoding/json"
)

// Block is one content block in a message, covering the three shapes the loop
// exchanges: model text, model tool calls, and our tool results.
type Block struct {
	Type      string          // "text" | "tool_use" | "tool_result"
	Text      string          // text, or tool_result payload
	ID        string          // tool_use: call id
	Name      string          // tool_use: tool name
	Input     json.RawMessage // tool_use: arguments
	ToolUseID string          // tool_result: id of the call being answered
	IsError   bool            // tool_result: the call was rejected or failed
}

// Message is one conversational turn.
type Message struct {
	Role    string // "user" | "assistant"
	Content []Block
}

// ToolDef declares a tool to the model.
type ToolDef struct {
	Name        string
	Description string
	Properties  map[string]any
	Required    []string
}

// Request is one model call.
type Request struct {
	Model    string
	System   string
	Messages []Message
	Tools    []ToolDef
	// Temperature is the sampling randomness, 0 in every production call: a
	// verdict is committed to the cache and gates builds, so one that flips
	// between runs on unchanged code is a defect, not variety. nil means "send
	// no temperature field at all" — a distinct request, not the same as 0,
	// and the shape reasoning models that reject the parameter need. Adapters
	// fall back to it on their own; nothing above them chooses.
	Temperature *float64
	MaxTokens   int
}

// Response is the model's reply plus token accounting for the budget.
type Response struct {
	Content      []Block
	StopReason   string
	InputTokens  int
	OutputTokens int
}

// Client is the LLM transport. The real implementation wraps the Anthropic
// SDK; tests use a fake that replays scripted transcripts.
type Client interface {
	Complete(ctx context.Context, req Request) (*Response, error)
}
