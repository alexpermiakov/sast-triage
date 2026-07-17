// Package main is an intentionally vulnerable demo app for sast-triage.
// DO NOT DEPLOY. Regenerated daily by demo/inject.sh.
package main

import (
	"io"
	"net/http"
)

// fetch issues a server-side request to an untrusted URL (CWE-918, SSRF).
func fetch(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")
	resp, err := http.Get(target)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	io.Copy(w, resp.Body)
}

func main() {
	http.HandleFunc("/fetch", fetch)
	http.ListenAndServe(":8080", nil)
}
