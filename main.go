// lucos_aithne — Passkey-based OpenID Provider for the lucOS estate.
//
// See ADR-0001 for the full design:
// https://github.com/lucas42/lucos_aithne/blob/main/docs/adr/0001-foundational-design.md
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"lucos_aithne/store"
)

const healthcheckTimeout = 5 * time.Second

// infoResponse is the `/_info` payload (Tier 1 + Tier 2 fields).
// Tier 3 fields (icon, show_on_homepage, etc.) are omitted — this is an API-only service.
type infoResponse struct {
	System  string         `json:"system"`
	Checks  map[string]any `json:"checks"`
	Metrics map[string]any `json:"metrics"`
	CI      *ciInfo        `json:"ci,omitempty"`
	Title   string         `json:"title,omitempty"`
}

type ciInfo struct {
	Circle string `json:"circle"`
}

func getEnvRequired(key string) string {
	val := os.Getenv(key)
	if val == "" {
		log.Fatalf("Required environment variable %s is not set", key)
	}
	return val
}

func handleInfo(system string, s *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		checks := map[string]any{}
		if err := s.Ping(); err != nil {
			checks["db"] = "error"
			log.Printf("/_info db ping failed: %v", err)
		} else {
			checks["db"] = "ok"
		}

		info := infoResponse{
			System:  system,
			Checks:  checks,
			Metrics: map[string]any{},
			CI:      &ciInfo{Circle: "gh/lucas42/lucos_aithne"},
			Title:   "Aithne",
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(info); err != nil {
			log.Printf("/_info encode error: %v", err)
		}
	}
}

// runHealthcheck performs a local HTTP check against /_info and exits 0/1.
// Called by the Docker HEALTHCHECK instruction.
func runHealthcheck(port string) {
	client := &http.Client{Timeout: healthcheckTimeout}
	url := fmt.Sprintf("http://127.0.0.1:%s/_info", port)
	resp, err := client.Get(url)
	if err != nil {
		fmt.Fprintf(os.Stderr, "healthcheck failed: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "healthcheck failed: /_info returned HTTP %d\n", resp.StatusCode)
		os.Exit(1)
	}
	os.Exit(0)
}

// ensureDir creates the parent directory of path if it does not already exist.
// This is a no-op for in-memory paths (e.g. ":memory:").
func ensureDir(path string) error {
	if path == ":memory:" || path == "" {
		return nil
	}
	dir := filepath.Dir(path)
	return os.MkdirAll(dir, 0o700)
}

func getEnvWithDefault(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

func main() {
	port := getEnvRequired("PORT")

	if len(os.Args) > 1 && os.Args[1] == "--healthcheck" {
		runHealthcheck(port)
	}

	system := getEnvRequired("SYSTEM")

	dbPath := getEnvWithDefault("DB_PATH", "/data/aithne.db")
	if err := ensureDir(dbPath); err != nil {
		log.Fatalf("Cannot create data directory for %q: %v", dbPath, err)
	}
	s, err := store.Open(dbPath)
	if err != nil {
		log.Fatalf("Failed to open principal/credential store at %q: %v", dbPath, err)
	}
	defer s.Close()
	log.Printf("Principal/credential store ready at %s", dbPath)

	mux := http.NewServeMux()
	mux.HandleFunc("/_info", handleInfo(system, s))

	addr := fmt.Sprintf(":%s", port)
	log.Printf("Starting lucos_aithne — system=%s, listening on %s", system, addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
