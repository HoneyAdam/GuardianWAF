package dashboard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// --- Events Export Tests ---

func TestHandleExportEvents_JSON(t *testing.T) {
	d := newTestDashboard(t, "test-key")

	// Store some events
	for i := 0; i < 5; i++ {
		evt := engine.Event{
			ID:        "evt-test-" + string(rune('0'+i)),
			Timestamp: time.Now(),
			ClientIP:  "192.168.1.1",
			Method:    "GET",
			Path:      "/test/path",
			Action:    engine.ActionBlock,
			Score:     50 + i*10,
			UserAgent: "TestBot/1.0",
		}
		d.eventStore.Store(evt)
	}

	req := authenticatedRequest("GET", "/api/v1/events/export?format=json", "", "test-key")
	rr := httptest.NewRecorder()
	d.mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}

	var result map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	evts, ok := result["events"].([]any)
	if !ok {
		t.Fatalf("expected events array, got %T", result["events"])
	}
	if len(evts) != 5 {
		t.Errorf("expected 5 events, got %d", len(evts))
	}
	count, ok := result["count"].(float64)
	if !ok || int(count) != 5 {
		t.Errorf("expected count=5, got %v (%T)", result["count"], result["count"])
	}
}

func TestHandleExportEvents_CSV(t *testing.T) {
	d := newTestDashboard(t, "test-key")

	// Store an event
	evt := engine.Event{
		ID:        "evt-csv-001",
		Timestamp: time.Now(),
		ClientIP:  "10.0.0.1",
		Method:    "POST",
		Path:      "/api/users",
		Action:    engine.ActionBlock,
		Score:     85,
		UserAgent: "Mozilla/5.0",
		Findings: []engine.Finding{
			{DetectorName: "sqli", Description: "SQL injection detected", Score: 50},
		},
	}
	d.eventStore.Store(evt)

	req := authenticatedRequest("GET", "/api/v1/events/export?format=csv", "", "test-key")
	rr := httptest.NewRecorder()
	d.mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}

	contentType := rr.Header().Get("Content-Type")
	if contentType != "text/csv" {
		t.Errorf("expected Content-Type text/csv, got %s", contentType)
	}

	body := rr.Body.String()
	// Check CSV header
	if !strings.Contains(body, "timestamp,event_id,client_ip") {
		t.Error("expected CSV header row")
	}
	// Check event data
	if !strings.Contains(body, "evt-csv-001") {
		t.Error("expected event ID in CSV")
	}
	if !strings.Contains(body, "10.0.0.1") {
		t.Error("expected client IP in CSV")
	}
}

func TestHandleExportEvents_InvalidFormat(t *testing.T) {
	d := newTestDashboard(t, "test-key")

	req := authenticatedRequest("GET", "/api/v1/events/export?format=xml", "", "test-key")
	rr := httptest.NewRecorder()
	d.mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", rr.Code)
	}

	var result map[string]any
	json.Unmarshal(rr.Body.Bytes(), &result)
	if !strings.Contains(result["error"].(string), "invalid format") {
		t.Error("expected 'invalid format' error message")
	}
}

func TestHandleExportEvents_DefaultFormat(t *testing.T) {
	d := newTestDashboard(t, "test-key")

	evt := engine.Event{
		ID:        "evt-default",
		Timestamp: time.Now(),
		ClientIP:  "127.0.0.1",
		Method:    "GET",
		Path:      "/",
		Action:    engine.ActionPass,
		Score:     0,
	}
	d.eventStore.Store(evt)

	// No format specified - should default to JSON
	req := authenticatedRequest("GET", "/api/v1/events/export", "", "test-key")
	rr := httptest.NewRecorder()
	d.mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}

	var result map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &result); err != nil {
		t.Fatalf("expected JSON response, got: %s", rr.Body.String())
	}
}

func TestHandleExportEvents_WithFilters(t *testing.T) {
	d := newTestDashboard(t, "test-key")

	// Store events with different actions
	d.eventStore.Store(engine.Event{
		ID:        "evt-block",
		Timestamp: time.Now(),
		ClientIP:  "192.168.1.1",
		Method:    "POST",
		Path:      "/api",
		Action:    engine.ActionBlock,
		Score:     75,
	})
	d.eventStore.Store(engine.Event{
		ID:        "evt-log",
		Timestamp: time.Now(),
		ClientIP:  "192.168.1.2",
		Method:    "GET",
		Path:      "/health",
		Action:    engine.ActionLog,
		Score:     30,
	})

	// Filter by action=blocked
	req := authenticatedRequest("GET", "/api/v1/events/export?format=json&action=blocked", "", "test-key")
	rr := httptest.NewRecorder()
	d.mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}

	var result map[string]any
	json.Unmarshal(rr.Body.Bytes(), &result)
	evts := result["events"].([]any)
	if len(evts) != 1 {
		t.Errorf("expected 1 block event, got %d", len(evts))
	}
}

func TestHandleExportEvents_WithMinScore(t *testing.T) {
	d := newTestDashboard(t, "test-key")

	d.eventStore.Store(engine.Event{
		ID:        "evt-low",
		Timestamp: time.Now(),
		ClientIP:  "1.2.3.4",
		Method:    "GET",
		Path:      "/",
		Action:    engine.ActionLog,
		Score:     25,
	})
	d.eventStore.Store(engine.Event{
		ID:        "evt-high",
		Timestamp: time.Now(),
		ClientIP:  "5.6.7.8",
		Method:    "POST",
		Path:      "/admin",
		Action:    engine.ActionBlock,
		Score:     75,
	})

	req := authenticatedRequest("GET", "/api/v1/events/export?format=json&min_score=50", "", "test-key")
	rr := httptest.NewRecorder()
	d.mux.ServeHTTP(rr, req)

	var result map[string]any
	json.Unmarshal(rr.Body.Bytes(), &result)
	evts := result["events"].([]any)
	if len(evts) != 1 {
		t.Errorf("expected 1 event with score >= 50, got %d", len(evts))
	}
}

func TestHandleExportEvents_Unauthorized(t *testing.T) {
	d := newTestDashboard(t, "test-key")

	req := authenticatedRequest("GET", "/api/v1/events/export?format=json", "", "")
	rr := httptest.NewRecorder()
	d.mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", rr.Code)
	}
}

func TestEscapeCSV(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"simple", "simple"},
		{"with,comma", "\"with,comma\""},
		{"with\"quote", "\"with\"\"quote\""},
		{"with\nnewline", "\"with\nnewline\""},
		{"with\r\rreturn", "\"with\r\rreturn\""},
		{"normal text 123", "normal text 123"},
	}

	for _, tt := range tests {
		result := escapeCSV(tt.input)
		if result != tt.expected {
			t.Errorf("escapeCSV(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestHandleExportEvents_EmptyStore(t *testing.T) {
	d := newTestDashboard(t, "test-key")

	req := authenticatedRequest("GET", "/api/v1/events/export?format=json", "", "test-key")
	rr := httptest.NewRecorder()
	d.mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}

	var result map[string]any
	json.Unmarshal(rr.Body.Bytes(), &result)

	// When empty, events may be nil or empty array
	evts, _ := result["events"].([]any)
	if len(evts) != 0 {
		t.Errorf("expected 0 events for empty store, got %d", len(evts))
	}

	count, ok := result["count"].(float64)
	if !ok || int(count) != 0 {
		t.Errorf("expected count=0, got %v (%T)", result["count"], result["count"])
	}
}
