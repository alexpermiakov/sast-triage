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

func TestCreateIssueHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"message":"Validation Failed"}`, http.StatusUnprocessableEntity)
	}))
	defer srv.Close()
	if _, err := NewForTest(srv.URL).CreateIssue(context.Background(), "t", "b", nil); err == nil {
		t.Fatal("want error on non-201")
	}
}
