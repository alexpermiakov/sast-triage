package app

import (
	"database/sql"
	"fmt"
	"net/http"
)

// Server wires HTTP handlers to the database.
type Server struct {
	db *sql.DB
}

// GetUser looks up a user by the id query parameter.
func (s *Server) GetUser(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	query := fmt.Sprintf("SELECT name, email FROM users WHERE id = %s", id)
	row := s.db.QueryRow(query)
	var name, email string
	if err := row.Scan(&name, &email); err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	fmt.Fprintf(w, "%s <%s>\n", name, email)
}
