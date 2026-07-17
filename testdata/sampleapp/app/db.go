package app

import "fmt"

// buildQuery formats a user lookup query for the given id.
func buildQuery(id string) string {
	return fmt.Sprintf("SELECT name FROM users WHERE id = %s", id)
}
