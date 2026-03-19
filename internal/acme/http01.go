package acme

import (
	"net/http"
	"strings"
	"sync"
)

// HTTP01Handler serves ACME HTTP-01 challenge responses.
// Mount it on the HTTP server to handle /.well-known/acme-challenge/ requests.
type HTTP01Handler struct {
	mu     sync.RWMutex
	tokens map[string]string // token -> keyAuthorization
}

// NewHTTP01Handler creates a new HTTP-01 challenge handler.
func NewHTTP01Handler() *HTTP01Handler {
	return &HTTP01Handler{
		tokens: make(map[string]string),
	}
}

// SetToken provisions a challenge token with its key authorization.
func (h *HTTP01Handler) SetToken(token, keyAuth string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.tokens[token] = keyAuth
}

// ClearToken removes a provisioned token.
func (h *HTTP01Handler) ClearToken(token string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.tokens, token)
}

// ServeHTTP handles HTTP-01 challenge validation requests.
// Responds with the key authorization for the requested token.
func (h *HTTP01Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Path: /.well-known/acme-challenge/<token>
	const prefix = "/.well-known/acme-challenge/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		http.NotFound(w, r)
		return
	}

	token := strings.TrimPrefix(r.URL.Path, prefix)
	if token == "" {
		http.NotFound(w, r)
		return
	}

	h.mu.RLock()
	keyAuth, ok := h.tokens[token]
	h.mu.RUnlock()

	if !ok {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = w.Write([]byte(keyAuth))
}
