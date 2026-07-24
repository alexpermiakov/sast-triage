package agent

import (
	"context"
	"fmt"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
)

// AnthropicClient is the production Client backed by the Anthropic API.
type AnthropicClient struct {
	client anthropic.Client
}

// NewAnthropicClient targets the Anthropic API. baseURL overrides the default
// endpoint (a gateway or proxy speaking the native API); empty uses the SDK's
// default. It is honoured rather than ignored so that a named endpoint is
// never silently traded for api.anthropic.com.
func NewAnthropicClient(apiKey, baseURL string) *AnthropicClient {
	opts := []option.RequestOption{option.WithAPIKey(apiKey)}
	if baseURL != "" {
		opts = append(opts, option.WithBaseURL(baseURL))
	}
	return &AnthropicClient{client: anthropic.NewClient(opts...)}
}

// Complete sends no sampling parameters. The project sends no temperature on any
// provider — the native API would in any case reject one, having removed
// temperature/top_p/top_k on the current Claude generation (Opus 4.8/4.7,
// Sonnet 5, Fable 5 answer a 400). Steer this provider with the prompt and
// -effort.
func (a *AnthropicClient) Complete(ctx context.Context, req Request) (*Response, error) {
	params := anthropic.MessageNewParams{
		Model:     anthropic.Model(req.Model),
		MaxTokens: int64(req.MaxTokens),
		System:    []anthropic.TextBlockParam{{Text: req.System}},
	}
	for _, m := range req.Messages {
		params.Messages = append(params.Messages, toMessageParam(m))
	}
	for _, t := range req.Tools {
		params.Tools = append(params.Tools, anthropic.ToolUnionParam{OfTool: &anthropic.ToolParam{
			Name:        t.Name,
			Description: anthropic.String(t.Description),
			InputSchema: anthropic.ToolInputSchemaParam{Properties: t.Properties, Required: t.Required},
		}})
	}
	msg, err := a.client.Messages.New(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("anthropic messages.create: %w", err)
	}

	resp := &Response{
		StopReason:   string(msg.StopReason),
		InputTokens:  int(msg.Usage.InputTokens),
		OutputTokens: int(msg.Usage.OutputTokens),
	}
	for _, b := range msg.Content {
		switch b.Type {
		case "text":
			resp.Content = append(resp.Content, Block{Type: "text", Text: b.Text})
		case "tool_use":
			resp.Content = append(resp.Content, Block{Type: "tool_use", ID: b.ID, Name: b.Name, Input: b.Input})
		}
	}
	return resp, nil
}

func toMessageParam(m Message) anthropic.MessageParam {
	var blocks []anthropic.ContentBlockParamUnion
	for _, b := range m.Content {
		switch b.Type {
		case "text":
			blocks = append(blocks, anthropic.NewTextBlock(b.Text))
		case "tool_use":
			blocks = append(blocks, anthropic.ContentBlockParamUnion{OfToolUse: &anthropic.ToolUseBlockParam{
				ID: b.ID, Name: b.Name, Input: b.Input,
			}})
		case "tool_result":
			blocks = append(blocks, anthropic.NewToolResultBlock(b.ToolUseID, b.Text, b.IsError))
		}
	}
	if m.Role == "assistant" {
		return anthropic.NewAssistantMessage(blocks...)
	}
	return anthropic.NewUserMessage(blocks...)
}
