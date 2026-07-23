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
	//
	// Honoured by the OpenAI-compatible adapter only. The native Anthropic API
	// removed the sampling parameters on the current Claude generation and
	// answers any of them with a 400, so anthropic.go drops this field rather
	// than failing every call; steer that provider with the prompt and -effort.
	Temperature *float64
	MaxTokens   int

	// ForceToolUse asks the provider to make at least one tool call this turn
	// instead of answering directly (OpenAI tool_choice "required"; Anthropic
	// tool_choice "any"). The loop sets it only on the first turn, and only when
	// tools are offered, to guarantee an evidence-gathering call before any
	// verdict — some models (Kimi K3 at its default reasoning_effort "max")
	// otherwise reason straight to a verdict from the prompt and never touch a
	// tool, which the minimum-evidence gate can only catch after the fact. Later
	// turns leave the choice to the model so it can emit the verdict. Ignored
	// where no tools are offered (context-free and short-circuit tiers).
	ForceToolUse bool
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
