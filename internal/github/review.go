package github

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// ReviewComment is one inline comment on a pull request diff.
type ReviewComment struct {
	Path string `json:"path"`
	Line int    `json:"line"`
	Body string `json:"body"`
}

// ListReviewComments returns the existing inline comments on a pull request.
// Bounded at 10 pages of 100: a PR past 1000 inline comments is not one this
// tool should add to. Used for dedupe — a re-run must not re-comment.
func (c *Client) ListReviewComments(ctx context.Context, pr int) ([]ReviewComment, error) {
	const perPage, maxPages = 100, 10
	var out []ReviewComment
	for page := 1; page <= maxPages; page++ {
		u := fmt.Sprintf("%s/repos/%s/pulls/%d/comments?per_page=%d&page=%d",
			c.baseURL, c.repo, pr, perPage, page)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, fmt.Errorf("list review comments: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+c.token)
		req.Header.Set("Accept", "application/vnd.github+json")

		resp, err := c.http.Do(req)
		if err != nil {
			return nil, fmt.Errorf("list review comments: %w", err)
		}
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("list review comments: %s: %s", resp.Status, truncate(string(data), 300))
		}
		var batch []ReviewComment
		if err := json.Unmarshal(data, &batch); err != nil {
			return nil, fmt.Errorf("list review comments: parse response: %w", err)
		}
		out = append(out, batch...)
		if len(batch) < perPage {
			break
		}
	}
	return out, nil
}

// ErrLineNotInDiff reports a comment rejected because its line is not part of
// the pull request diff. It is expected, not exceptional: full-scope runs and
// findings whose flagged line sits in an unchanged hunk of a changed file both
// hit it. Callers degrade to a log line — the finding still reaches the report,
// the digest, and the gate.
var ErrLineNotInDiff = fmt.Errorf("line is not part of the pull request diff")

// CreateReviewComment posts one inline comment on the pull request diff at
// path:line of commitID, on the post-change side.
//
// GitHub rejects a line outside the diff with 422; that is surfaced as
// ErrLineNotInDiff so the caller can skip it quietly rather than treat a
// routine miss as a failure.
func (c *Client) CreateReviewComment(ctx context.Context, pr int, path string, line int, commitID, body string) error {
	payload, err := json.Marshal(map[string]any{
		"body":      body,
		"path":      path,
		"line":      line,
		"side":      "RIGHT",
		"commit_id": commitID,
	})
	if err != nil {
		return fmt.Errorf("create review comment: %w", err)
	}
	u := fmt.Sprintf("%s/repos/%s/pulls/%d/comments", c.baseURL, c.repo, pr)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("create review comment: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("create review comment: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	switch resp.StatusCode {
	case http.StatusCreated:
		return nil
	case http.StatusUnprocessableEntity:
		return fmt.Errorf("%s:%d: %w", path, line, ErrLineNotInDiff)
	default:
		return fmt.Errorf("create review comment %s:%d: %s: %s",
			path, line, resp.Status, truncate(string(data), 300))
	}
}
