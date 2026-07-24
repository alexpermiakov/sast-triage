package github

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A pull request's conversation comments live on the ISSUES endpoint, not the
// pulls one — /pulls/{n}/comments is the different thing, comments anchored to
// a line of the diff. Sending the summary there would attach it to nothing.
func TestCreateIssueComment(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/o/r/issues/42/comments" || r.Method != http.MethodPost {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &got)
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"id": 1}`))
	}))
	defer srv.Close()

	if err := NewForTest(srv.URL).CreateIssueComment(context.Background(), 42, "3 findings suppressed"); err != nil {
		t.Fatal(err)
	}
	if got["body"] != "3 findings suppressed" {
		t.Errorf("body = %+v", got)
	}
}

func TestCreateIssueCommentError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"message": "Resource not accessible by integration"}`))
	}))
	defer srv.Close()

	err := NewForTest(srv.URL).CreateIssueComment(context.Background(), 42, "body")
	if err == nil {
		t.Fatal("want an error on 403")
	}
	// The caller degrades to a log line, so the line has to say what happened.
	if !strings.Contains(err.Error(), "not accessible") {
		t.Errorf("error = %v, want the API's own message carried through", err)
	}
}

// Dedupe reads every existing comment, so pagination is load-bearing: a marker
// stranded on page two means a duplicate comment on every run.
func TestListIssueCommentsPaginates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var batch []string
		switch r.URL.Query().Get("page") {
		case "1":
			for i := 0; i < 100; i++ {
				batch = append(batch, fmt.Sprintf(`{"body": "c%d"}`, i))
			}
		case "2":
			batch = []string{`{"body": "sast-triage marker"}`}
		}
		w.Write([]byte("[" + strings.Join(batch, ",") + "]"))
	}))
	defer srv.Close()

	got, err := NewForTest(srv.URL).ListIssueComments(context.Background(), 42)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 101 {
		t.Fatalf("got %d comments, want both pages (101)", len(got))
	}
	if got[100].Body != "sast-triage marker" {
		t.Errorf("last comment = %q, want the one from page 2", got[100].Body)
	}
}
