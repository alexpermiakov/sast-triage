package github

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCreateIssue(t *testing.T) {
	var got struct {
		Title  string   `json:"title"`
		Body   string   `json:"body"`
		Labels []string `json:"labels"`
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/o/r/issues" || r.Method != http.MethodPost {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Error("missing auth header")
		}
		json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"number": 77}`))
	}))
	defer srv.Close()

	n, err := NewForTest(srv.URL).CreateIssue(context.Background(), "title", "body", []string{"security/triage-confirmed"})
	if err != nil {
		t.Fatal(err)
	}
	if n != 77 {
		t.Errorf("number = %d, want 77", n)
	}
	if got.Title != "title" || got.Labels[0] != "security/triage-confirmed" {
		t.Errorf("payload = %+v", got)
	}
}

func TestListIssues(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/o/r/issues" || r.Method != http.MethodGet {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		q := r.URL.Query()
		if q.Get("state") != "all" || q.Get("labels") != "security/triage-confirmed" {
			t.Errorf("query = %s (closed issues must dedupe too)", r.URL.RawQuery)
		}
		if q.Get("page") != "1" {
			// A short first page must end pagination.
			t.Errorf("unexpected page %s", q.Get("page"))
		}
		w.Write([]byte(`[
			{"number": 78, "title": "real issue", "body": "<!-- sast-triage:fingerprint:abc_0 -->"},
			{"number": 79, "title": "a PR, not an issue", "body": "", "pull_request": {"url": "x"}}
		]`))
	}))
	defer srv.Close()

	issues, err := NewForTest(srv.URL).ListIssues(context.Background(), "security/triage-confirmed")
	if err != nil {
		t.Fatal(err)
	}
	if len(issues) != 1 || issues[0].Number != 78 || issues[0].Body == "" {
		t.Errorf("issues = %+v, want just #78 with body (PRs skipped)", issues)
	}
}

func TestListIssuesHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"message":"nope"}`, http.StatusForbidden)
	}))
	defer srv.Close()
	if _, err := NewForTest(srv.URL).ListIssues(context.Background(), "l"); err == nil {
		t.Fatal("want error on non-200")
	}
}

func TestCreateIssueHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"message":"Validation Failed"}`, http.StatusUnprocessableEntity)
	}))
	defer srv.Close()
	if _, err := NewForTest(srv.URL).CreateIssue(context.Background(), "t", "b", nil); err == nil {
		t.Fatal("want error on non-201")
	}
}
