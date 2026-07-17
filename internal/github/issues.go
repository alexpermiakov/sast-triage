// Package github is a minimal Issues client for routing exploitable verdicts.
// Deduplication is owned by the cache (issueRef != 0 → already filed), so this
// client only creates.
package github

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type Client struct {
	token   string
	repo    string // "owner/name"
	baseURL string
	http    *http.Client
}

func New(token, repo string) *Client {
	return &Client{
		token:   token,
		repo:    repo,
		baseURL: "https://api.github.com",
		http:    &http.Client{Timeout: 30 * time.Second},
	}
}

// NewForTest points the client at a fake API server.
func NewForTest(baseURL string) *Client {
	c := New("test-token", "o/r")
	c.baseURL = baseURL
	return c
}

// CreateIssue files one issue and returns its number.
func (c *Client) CreateIssue(ctx context.Context, title, body string, labels []string) (int, error) {
	payload, err := json.Marshal(map[string]any{
		"title": title, "body": body, "labels": labels,
	})
	if err != nil {
		return 0, fmt.Errorf("create issue: %w", err)
	}
	url := fmt.Sprintf("%s/repos/%s/issues", c.baseURL, c.repo)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return 0, fmt.Errorf("create issue: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return 0, fmt.Errorf("create issue: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusCreated {
		return 0, fmt.Errorf("create issue: %s: %s", resp.Status, truncate(string(data), 300))
	}
	var out struct {
		Number int `json:"number"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return 0, fmt.Errorf("create issue: parse response: %w", err)
	}
	return out.Number, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
