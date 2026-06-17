package main

// requestlog.go — request-scoped correlation ID logging.
//
// withRequestLogger is HTTP middleware that generates a UUID correlation ID for
// each incoming request and attaches a *log.Logger (prefixed with that ID) to
// the request context. All handler log calls should use reqLogger(r) rather than
// the package-level log.Printf so that their output is tagged with the ID.
//
// Startup and CLI-path log calls (bootstrap, main, runRekey, etc.) are not
// request-scoped and continue to use log.Printf directly.

import (
	"context"
	"log"
	"net/http"

	"github.com/google/uuid"
)

// ctxLogKey is the typed context key used to store the per-request logger.
type ctxLogKey struct{}

// withRequestLogger wraps next: generates a short request correlation ID,
// creates a *log.Logger prefixed with [reqID=<id>], stores it in the request
// context, and calls next with the updated request.
func withRequestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Use the first 8 characters of a random UUID v4 as the correlation ID.
		// Collision probability is negligible for request-grouping purposes.
		reqID := uuid.New().String()[:8]
		logger := log.New(log.Writer(), "[reqID="+reqID+"] ", log.LstdFlags)
		ctx := context.WithValue(r.Context(), ctxLogKey{}, logger)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// reqLogger returns the request-scoped *log.Logger from r's context.
// Falls back to log.Default() when the middleware is not in the chain
// (e.g. tests that construct requests directly with httptest.NewRequest).
func reqLogger(r *http.Request) *log.Logger {
	if l, ok := r.Context().Value(ctxLogKey{}).(*log.Logger); ok {
		return l
	}
	return log.Default()
}
