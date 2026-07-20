package github

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCreateReviewComment(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/o/r/pulls/42/comments" || r.Method != http.MethodPost {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &got)
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"id": 1}`))
	}))
	defer srv.Close()

	c := NewForTest(srv.URL)
	err := c.CreateReviewComment(context.Background(), 42, "app/handlers.go", 17, "abc123", "exploitable")
	if err != nil {
		t.Fatal(err)
	}
	if got["path"] != "app/handlers.go" || got["line"] != float64(17) {
		t.Errorf("anchor = %+v", got)
	}
	if got["commit_id"] != "abc123" || got["side"] != "RIGHT" {
		t.Errorf("comment must anchor to the post-change side of the head commit: %+v", got)
	}
}

// A line outside the diff is routine, not exceptional: a finding can sit in an
// unchanged hunk of a changed file. It must be distinguishable so the caller
// skips it quietly instead of logging a scary failure.
func TestCreateReviewCommentLineNotInDiff(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		w.Write([]byte(`{"message": "line must be part of the diff"}`))
	}))
	defer srv.Close()

	err := NewForTest(srv.URL).CreateReviewComment(context.Background(), 42, "a.go", 9, "sha", "body")
	if !errors.Is(err, ErrLineNotInDiff) {
		t.Errorf("err = %v, want ErrLineNotInDiff", err)
	}
	if !strings.Contains(err.Error(), "a.go:9") {
		t.Errorf("err = %v, want the location in the message", err)
	}
}

func TestCreateReviewCommentServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"message": "Resource not accessible by integration"}`))
	}))
	defer srv.Close()

	err := NewForTest(srv.URL).CreateReviewComment(context.Background(), 42, "a.go", 9, "sha", "body")
	if err == nil || errors.Is(err, ErrLineNotInDiff) {
		t.Errorf("err = %v, want a plain failure (a read-only token is not a diff problem)", err)
	}
}

func TestListReviewCommentsPaginates(t *testing.T) {
	page1 := make([]ReviewComment, 100)
	for i := range page1 {
		page1[i] = ReviewComment{Path: "a.go", Line: i + 1, Body: "first page"}
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("page") == "1" {
			json.NewEncoder(w).Encode(page1)
			return
		}
		json.NewEncoder(w).Encode([]ReviewComment{{Path: "b.go", Line: 3, Body: "second page"}})
	}))
	defer srv.Close()

	got, err := NewForTest(srv.URL).ListReviewComments(context.Background(), 42)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 101 {
		t.Fatalf("got %d comments, want 101 across two pages", len(got))
	}
	if got[100].Body != "second page" {
		t.Errorf("last comment = %+v", got[100])
	}
}
