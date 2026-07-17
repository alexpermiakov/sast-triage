// Package main is a small, intentionally vulnerable app used as a FIXED target
// for the sast-triage demo workflow. DO NOT DEPLOY. It is committed by hand and
// never generated; the workflow only scans and triages it.
package main

import (
	"database/sql"
	"fmt"
	"io"
	"net/http"
	"os/exec"
)

// dbPassword is a hardcoded credential (CWE-798) — exercises the context-free tier.
const dbPassword = "hunter2-prod-password"

var db *sql.DB

// lookupUser builds a SQL query from untrusted input (CWE-89, SQL injection).
func lookupUser(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	query := fmt.Sprintf("SELECT name, email FROM users WHERE id = %s", id)
	row := db.QueryRow(query)
	var name, email string
	if err := row.Scan(&name, &email); err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	fmt.Fprintf(w, "%s <%s>\n", name, email)
}

// ping runs a shell command assembled from untrusted input (CWE-78, command injection).
func ping(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	out, err := exec.Command("sh", "-c", "ping -c 1 "+host).CombinedOutput()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write(out)
}

// fetch performs a server-side request to an untrusted URL (CWE-918, SSRF).
func fetch(w http.ResponseWriter, r *http.Request) {
	resp, err := http.Get(r.URL.Query().Get("url"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	io.Copy(w, resp.Body)
}

func main() {
	http.HandleFunc("/user", lookupUser)
	http.HandleFunc("/ping", ping)
	http.HandleFunc("/fetch", fetch)
	http.ListenAndServe(":8080", nil)
}
