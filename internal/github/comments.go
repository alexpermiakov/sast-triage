package github

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// IssueComment is one comment on a pull request's conversation tab. Pull
// requests are issues as far as this endpoint is concerned, which is why a PR
// number goes to /issues/{n}/comments — the /pulls/{n}/comments endpoint in
// review.go is the different thing: comments anchored to a line of the diff.
type IssueComment struct {
	Body string `json:"body"`
}

// ListIssueComments returns the conversation comments on a pull request.
// Bounded at 10 pages of 100 for the reason ListReviewComments is: a thread
// past 1000 comments is not one this tool should be adding to. Used for dedupe.
func (c *Client) ListIssueComments(ctx context.Context, issue int) ([]IssueComment, error) {
	const perPage, maxPages = 100, 10
	var out []IssueComment
	for page := 1; page <= maxPages; page++ {
		u := fmt.Sprintf("%s/repos/%s/issues/%d/comments?per_page=%d&page=%d",
			c.baseURL, c.repo, issue, perPage, page)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, fmt.Errorf("list issue comments: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+c.token)
		req.Header.Set("Accept", "application/vnd.github+json")

		resp, err := c.http.Do(req)
		if err != nil {
			return nil, fmt.Errorf("list issue comments: %w", err)
		}
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("list issue comments: %s: %s", resp.Status, truncate(string(data), 300))
		}
		var batch []IssueComment
		if err := json.Unmarshal(data, &batch); err != nil {
			return nil, fmt.Errorf("list issue comments: parse response: %w", err)
		}
		out = append(out, batch...)
		if len(batch) < perPage {
			break
		}
	}
	return out, nil
}

// CreateIssueComment posts one comment on a pull request's conversation.
func (c *Client) CreateIssueComment(ctx context.Context, issue int, body string) error {
	payload, err := json.Marshal(map[string]any{"body": body})
	if err != nil {
		return fmt.Errorf("create issue comment: %w", err)
	}
	u := fmt.Sprintf("%s/repos/%s/issues/%d/comments", c.baseURL, c.repo, issue)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("create issue comment: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("create issue comment: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("create issue comment: %s: %s", resp.Status, truncate(string(data), 300))
	}
	return nil
}
