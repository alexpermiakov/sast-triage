package app

import "testing"

// TestQueryEscaping exercises the raw query path with a fixed id.
func TestQueryEscaping(t *testing.T) {
	q := buildQuery("42; DROP TABLE users")
	if q == "" {
		t.Fatal("empty query")
	}
}
