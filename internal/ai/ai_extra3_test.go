package ai

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// errorReader always fails
type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, errors.New("read error") }
func (errorReader) Close() error             { return nil }

// errorBodyTransport returns 200 with a body that errors on read
type errorBodyTransport struct{}

func (errorBodyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(errorReader{}),
		Header:     make(http.Header),
		Request:    req,
	}, nil
}

func TestAnalyze_ReadBodyError(t *testing.T) {
	c := NewClient(ClientConfig{BaseURL: "https://example.com", APIKey: "test"})
	c.httpClient = &http.Client{Transport: errorBodyTransport{}}

	_, _, err := c.Analyze(context.Background(), "system", "user")
	if err == nil {
		t.Error("expected error when response body read fails")
	}
}

func TestFetchCatalog_ReadBodyError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Fatal("cannot hijack")
		}
		conn, _, _ := hj.Hijack()
		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n"))
		_, _ = conn.Write([]byte("short"))
		_ = conn.Close()
	}))
	defer srv.Close()

	_, err := FetchCatalog(srv.URL + "/catalog.json")
	if err == nil {
		t.Error("expected error for incomplete response body")
	}
}
