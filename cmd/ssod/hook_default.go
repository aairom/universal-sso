//go:build !e2e

package main

import "net/http"

// wrap returns h unchanged. The end-to-end build (-tags e2e) replaces it with
// a variant that also serves fake identity providers; see hook_e2e.go.
func wrap(h http.Handler, _ func(string) string) (http.Handler, error) { return h, nil }
