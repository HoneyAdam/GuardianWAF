package mcp

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHandleGetTopIPs_InvalidJSON(t *testing.T) {
	srv := NewServer(nil, nil)
	srv.SetEngine(newMockEngine())
	_, err := srv.handleGetTopIPs(json.RawMessage("not-json"))
	if err == nil {
		t.Fatal("expected error for invalid JSON params")
	}
}

func TestWriteResponse_MarshalError(t *testing.T) {
	var buf bytes.Buffer
	srv := NewServer(nil, &buf)
	srv.writeResponse(JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      1,
		Result:  make(chan int),
	})
	if buf.Len() != 0 {
		t.Error("expected no output when marshal fails")
	}
}

func TestHandleSSE_NonFlusher(t *testing.T) {
	handler, _ := helperSSEServer("")
	rec := httptest.NewRecorder()
	nf := &struct {
		http.ResponseWriter
	}{ResponseWriter: rec}
	req := httptest.NewRequest(http.MethodGet, "/mcp/sse", nil)
	handler.handleSSE(nf, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rec.Code)
	}
}

func TestHandleSSE_HTTPS(t *testing.T) {
	handler, _ := helperSSEServer("")
	rec := httptest.NewRecorder()
	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodGet, "/mcp/sse", nil).WithContext(ctx)
	req.TLS = &tls.ConnectionState{}

	done := make(chan struct{})
	go func() {
		handler.handleSSE(rec, req)
		close(done)
	}()

	// Wait for SSE data with timeout
	var bodyStr string
	for i := 0; i < 200; i++ {
		time.Sleep(10 * time.Millisecond)
		bodyStr = rec.Body.String()
		if len(bodyStr) > 0 {
			break
		}
	}
	if len(bodyStr) == 0 {
		t.Fatal("timed out waiting for SSE data")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for handleSSE to return")
	}

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	body := bodyStr
	if !bytes.Contains([]byte(body), []byte("https://")) {
		t.Fatalf("expected https scheme in endpoint, got %s", body)
	}
}

func TestBroadcastResponse_MarshalError(t *testing.T) {
	handler, _ := helperSSEServer("")
	handler.broadcastResponse(JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      1,
		Result:  math.NaN(),
	})
}
