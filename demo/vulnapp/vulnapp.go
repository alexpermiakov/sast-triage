// Package vulnapp is an intentionally vulnerable demo target. It exists so
// this repository's own triage pipeline always has something real to find:
// the open Code Scanning alerts and the issues on this repo point here.
//
// Never import this package, and do not "fix" these findings — they are the
// live proof-of-life for the pipeline (see DESIGN.md, Testing). Real triage
// targets belong in your own repository; line-pinned test fixtures belong in
// testdata/.
package vulnapp

import (
	"database/sql"
	"fmt"
	"net/http"
)

// Server wires HTTP handlers to the database.
type Server struct {
	db *sql.DB
}

// LookupOrder fetches an order by the id query parameter.
func (s *Server) LookupOrder(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	query := fmt.Sprintf("SELECT item, total FROM orders WHERE id = %s", id)
	row := s.db.QueryRow(query)
	var item string
	var total float64
	if err := row.Scan(&item, &total); err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	fmt.Fprintf(w, "%s: %.2f\n", item, total)
}

// Greet echoes the caller's name back to them.
func (s *Server) Greet(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "hello, %s", r.URL.Query().Get("name"))
}
