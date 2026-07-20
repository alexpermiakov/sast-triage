// Package github is a minimal Issues + pull-request-review client for routing
// verdicts to where people already look. Issue deduplication is owned by the
// cache (issueRef != 0 → already filed); listing exists so filing can adopt an
// already-filed issue when the cache entry lost its issueRef (e.g. the run that
// filed it never landed on this branch). Review comments dedupe on the
// fingerprint marker in the body, because they are not recorded in the cache —
// a comment belongs to one PR, the cache outlives every PR.
package github

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
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

// Issue is one existing issue — the fields dedupe matches on.
type Issue struct {
	Number int    `json:"number"`
	Title  string `json:"title"`
	Body   string `json:"body"`
}

// ListIssues returns issues carrying the label, open and closed, newest first.
// Bounded: at most 10 pages of 100 — a triage label past 1000 issues is a
// process problem, not a pagination problem. Pull requests share the issues
// endpoint and are skipped.
func (c *Client) ListIssues(ctx context.Context, label string) ([]Issue, error) {
	const perPage, maxPages = 100, 10
	var out []Issue
	for page := 1; page <= maxPages; page++ {
		u := fmt.Sprintf("%s/repos/%s/issues?state=all&labels=%s&per_page=%d&page=%d",
			c.baseURL, c.repo, url.QueryEscape(label), perPage, page)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, fmt.Errorf("list issues: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+c.token)
		req.Header.Set("Accept", "application/vnd.github+json")

		resp, err := c.http.Do(req)
		if err != nil {
			return nil, fmt.Errorf("list issues: %w", err)
		}
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("list issues: %s: %s", resp.Status, truncate(string(data), 300))
		}
		var batch []struct {
			Issue
			PullRequest *struct{} `json:"pull_request"`
		}
		if err := json.Unmarshal(data, &batch); err != nil {
			return nil, fmt.Errorf("list issues: parse response: %w", err)
		}
		for _, it := range batch {
			if it.PullRequest == nil {
				out = append(out, it.Issue)
			}
		}
		if len(batch) < perPage {
			break
		}
	}
	return out, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
