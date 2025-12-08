package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
)

// Simple WeChat callback relay. It accepts code/state from WeChat and
// returns them to the desktop client either via custom scheme redirect
// or plain JSON.
func main() {
	http.HandleFunc("/wechat/callback", handleCallback)

	port := getenv("PORT", "7000")
	log.Printf("callback-service listening on :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

func handleCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	if code == "" {
		http.Error(w, "missing code", http.StatusBadRequest)
		return
	}

	// Optional state check to prevent CSRF replay.
	if allowed := os.Getenv("WECHAT_ALLOWED_STATE"); allowed != "" && state != allowed {
		http.Error(w, "invalid state", http.StatusBadRequest)
		return
	}

	// If a custom scheme is provided, redirect so the desktop app can capture it.
	if scheme := os.Getenv("WECHAT_CLIENT_SCHEME"); scheme != "" {
		redirect := fmt.Sprintf("%s?code=%s&state=%s", scheme, code, state)
		http.Redirect(w, r, redirect, http.StatusFound)
		return
	}

	// Fallback: return code/state as JSON for polling/HTTP fetch.
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"code":"%s","state":"%s"}`, code, state)
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

