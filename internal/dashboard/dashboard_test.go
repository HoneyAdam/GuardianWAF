package dashboard

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/events"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// stubEventBus satisfies engine.EventPublisher for testing.
type stubEventBus struct{}

func (s *stubEventBus) Subscribe(ch chan<- engine.Event) {}
func (s *stubEventBus) Publish(event engine.Event)       {}
func (s *stubEventBus) Close()                           {}

// stubEventStore satisfies engine.EventStorer for testing.
type stubEventStore struct{}

func (s *stubEventStore) Store(event engine.Event) error { return nil }
func (s *stubEventStore) Close() error                   { return nil }

func testConfig() *config.Config {
	return &config.Config{
		Mode:   "enforce",
		Listen: ":8080",
		WAF: config.WAFConfig{
			Sanitizer: config.SanitizerConfig{
				MaxBodySize: 1 << 20,
			},
			Detection: config.DetectionConfig{
				Threshold: config.ThresholdConfig{
					Block: 50,
					Log:   25,
				},
			},
		},
		Dashboard: config.DashboardConfig{
			Enabled: true,
			Listen:  ":9090",
		},
	}
}

func testEngine(t *testing.T) *engine.Engine {
	t.Helper()
	cfg := testConfig()
	eng, err := engine.NewEngine(cfg, &stubEventStore{}, &stubEventBus{})
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}
	return eng
}

func testDashboard(t *testing.T, apiKey string) *Dashboard {
	t.Helper()
	eng := testEngine(t)
	store := events.NewMemoryStore(1024)
	return NewDashboard(eng, store, apiKey)
}

// ---------------------------------------------------------------------------
// API Key Auth Tests
// ---------------------------------------------------------------------------

func TestAuthMiddleware_NoKey(t *testing.T) {
	d := testDashboard(t, "")
	ts := httptest.NewServer(d.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/v1/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 with no auth, got %d", resp.StatusCode)
	}
}

func TestAuthMiddleware_ValidKey(t *testing.T) {
	apiKey := "test-secret-key-123"
	d := testDashboard(t, apiKey)
	ts := httptest.NewServer(d.Handler())
	defer ts.Close()

	req, _ := http.NewRequest("GET", ts.URL+"/api/v1/health", nil)
	req.Header.Set("X-GuardianWAF-Key", apiKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 with valid key, got %d", resp.StatusCode)
	}
}

func TestAuthMiddleware_InvalidKey(t *testing.T) {
	apiKey := "test-secret-key-123"
	d := testDashboard(t, apiKey)
	ts := httptest.NewServer(d.Handler())
	defer ts.Close()

	req, _ := http.NewRequest("GET", ts.URL+"/api/v1/health", nil)
	req.Header.Set("X-GuardianWAF-Key", "wrong-key")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 with wrong key, got %d", resp.StatusCode)
	}
}

func TestAuthMiddleware_QueryParamKey(t *testing.T) {
	apiKey := "test-secret-key-123"
	d := testDashboard(t, apiKey)
	ts := httptest.NewServer(d.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/v1/health?api_key=" + apiKey)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 with query param key, got %d", resp.StatusCode)
	}
}

func TestAuthMiddleware_MissingKey(t *testing.T) {
	apiKey := "test-secret-key-123"
	d := testDashboard(t, apiKey)
	ts := httptest.NewServer(d.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/v1/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 with missing key, got %d", resp.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// Stats Endpoint
// ---------------------------------------------------------------------------

func TestGetStats(t *testing.T) {
	d := testDashboard(t, "")
	ts := httptest.NewServer(d.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/v1/stats")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var data map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		t.Fatalf("failed to decode JSON: %v", err)
	}

	for _, field := range []string{"total_requests", "blocked_requests", "logged_requests", "passed_requests", "avg_latency_us"} {
		if _, ok := data[field]; !ok {
			t.Errorf("missing expected field %q in stats response", field)
		}
	}
}

// ---------------------------------------------------------------------------
// Events Endpoints
// ---------------------------------------------------------------------------

func TestGetEvents(t *testing.T) {
	d := testDashboard(t, "")
	ts := httptest.NewServer(d.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/v1/events")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var data map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		t.Fatalf("failed to decode JSON: %v", err)
	}

	if _, ok := data["events"]; !ok {
		t.Error("missing 'events' field")
	}
	if _, ok := data["total"]; !ok {
		t.Error("missing 'total' field")
	}
}

func TestGetEvents_Pagination(t *testing.T) {
	d := testDashboard(t, "")
	ts := httptest.NewServer(d.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/v1/events?limit=5&offset=0")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var data map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		t.Fatalf("failed to decode JSON: %v", err)
	}

	limit, ok := data["limit"]
	if !ok {
		t.Fatal("missing 'limit' in response")
	}
	if int(limit.(float64)) != 5 {
		t.Errorf("expected limit 5, got %v", limit)
	}
}

func TestGetEvent_NotFound(t *testing.T) {
	d := testDashboard(t, "")
	ts := httptest.NewServer(d.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/v1/events/nonexistent-id")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// Health Endpoint
// ---------------------------------------------------------------------------

func TestHealth(t *testing.T) {
	d := testDashboard(t, "")
	ts := httptest.NewServer(d.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/v1/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var data map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		t.Fatal(err)
	}
	if data["status"] != "healthy" {
		t.Errorf("expected status 'healthy', got %v", data["status"])
	}
}

// ---------------------------------------------------------------------------
// Version Endpoint
// ---------------------------------------------------------------------------

func TestVersion(t *testing.T) {
	d := testDashboard(t, "")
	ts := httptest.NewServer(d.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/v1/version")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var data map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		t.Fatal(err)
	}
	if data["version"] != Version {
		t.Errorf("expected version %q, got %v", Version, data["version"])
	}
	if data["name"] != "GuardianWAF" {
		t.Errorf("expected name 'GuardianWAF', got %v", data["name"])
	}
}

// ---------------------------------------------------------------------------
// SSE Endpoint
// ---------------------------------------------------------------------------

func TestSSEEndpoint(t *testing.T) {
	d := testDashboard(t, "")
	ts := httptest.NewServer(d.Handler())
	defer ts.Close()

	// Just check it returns the SSE content-type and starts streaming
	req, _ := http.NewRequest("GET", ts.URL+"/api/v1/sse", nil)
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	ct := resp.Header.Get("Content-Type")
	if ct != "text/event-stream" {
		t.Errorf("expected Content-Type text/event-stream, got %q", ct)
	}

	// Read the initial connection message
	buf := make([]byte, 512)
	n, _ := resp.Body.Read(buf)
	data := string(buf[:n])
	if !strings.Contains(data, "connected") {
		t.Errorf("expected initial 'connected' event, got %q", data)
	}
}

// ---------------------------------------------------------------------------
// Static File Serving
// ---------------------------------------------------------------------------

func TestServeIndex(t *testing.T) {
	d := testDashboard(t, "")
	ts := httptest.NewServer(d.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Errorf("expected text/html, got %q", ct)
	}
}

func TestServeJS(t *testing.T) {
	d := testDashboard(t, "")
	ts := httptest.NewServer(d.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/app.js")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "javascript") {
		t.Errorf("expected javascript content type, got %q", ct)
	}
}

func TestServeCSS(t *testing.T) {
	d := testDashboard(t, "")
	ts := httptest.NewServer(d.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/style.css")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "css") {
		t.Errorf("expected css content type, got %q", ct)
	}
}

func TestServe404(t *testing.T) {
	d := testDashboard(t, "")
	ts := httptest.NewServer(d.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/nonexistent")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// GenerateAPIKey
// ---------------------------------------------------------------------------

func TestGenerateAPIKey(t *testing.T) {
	key := GenerateAPIKey()
	if len(key) != 64 {
		t.Fatalf("expected 64-char hex string, got %d chars: %q", len(key), key)
	}

	// Ensure it's valid hex
	for _, c := range key {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Fatalf("invalid hex character %q in key %q", string(c), key)
		}
	}

	// Keys should be unique
	key2 := GenerateAPIKey()
	if key == key2 {
		t.Fatal("two generated keys should not be equal")
	}
}

// ---------------------------------------------------------------------------
// SSE Broadcaster
// ---------------------------------------------------------------------------

func TestSSEBroadcasterClientCount(t *testing.T) {
	b := NewSSEBroadcaster()
	if b.ClientCount() != 0 {
		t.Fatalf("expected 0 clients, got %d", b.ClientCount())
	}

	ch := make(chan string, 64)
	b.addClient(ch)
	if b.ClientCount() != 1 {
		t.Fatalf("expected 1 client, got %d", b.ClientCount())
	}

	b.removeClient(ch)
	if b.ClientCount() != 0 {
		t.Fatalf("expected 0 clients after remove, got %d", b.ClientCount())
	}
}

func TestSSEBroadcasterBroadcast(t *testing.T) {
	b := NewSSEBroadcaster()

	ch1 := make(chan string, 64)
	ch2 := make(chan string, 64)
	b.addClient(ch1)
	b.addClient(ch2)

	b.Broadcast("test", `{"hello":"world"}`)

	msg1 := <-ch1
	msg2 := <-ch2

	if !strings.Contains(msg1, "test") {
		t.Errorf("ch1 message missing event type: %q", msg1)
	}
	if !strings.Contains(msg2, "hello") {
		t.Errorf("ch2 message missing data: %q", msg2)
	}

	b.removeClient(ch1)
	b.removeClient(ch2)
}

// ---------------------------------------------------------------------------
// Whitelist CRUD
// ---------------------------------------------------------------------------

func TestWhitelistCRUD(t *testing.T) {
	d := testDashboard(t, "")
	ts := httptest.NewServer(d.Handler())
	defer ts.Close()

	// List (empty)
	resp, err := http.Get(ts.URL + "/api/v1/rules/whitelist")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list: expected 200, got %d", resp.StatusCode)
	}

	// Add
	body := strings.NewReader(`{"value":"192.168.1.0/24","reason":"internal"}`)
	resp, err = http.Post(ts.URL+"/api/v1/rules/whitelist", "application/json", body)
	if err != nil {
		t.Fatal(err)
	}
	var entry RuleEntry
	json.NewDecoder(resp.Body).Decode(&entry)
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("add: expected 201, got %d", resp.StatusCode)
	}
	if entry.ID == "" {
		t.Fatal("add: expected non-empty ID")
	}

	// Delete
	req, _ := http.NewRequest("DELETE", ts.URL+"/api/v1/rules/whitelist/"+entry.ID, nil)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("delete: expected 200, got %d", resp.StatusCode)
	}

	// Delete non-existent
	req, _ = http.NewRequest("DELETE", ts.URL+"/api/v1/rules/whitelist/999", nil)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("delete non-existent: expected 404, got %d", resp.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// Config Endpoints
// ---------------------------------------------------------------------------

func TestGetConfig(t *testing.T) {
	d := testDashboard(t, "")
	ts := httptest.NewServer(d.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/v1/config")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestReloadConfig(t *testing.T) {
	d := testDashboard(t, "")
	ts := httptest.NewServer(d.Handler())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/api/v1/config/reload", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// UpdateConfig endpoint
// ---------------------------------------------------------------------------

func TestUpdateConfig(t *testing.T) {
	d := testDashboard(t, "")
	ts := httptest.NewServer(d.Handler())
	defer ts.Close()

	body := strings.NewReader(`{"mode":"monitor","threshold":75}`)
	req, _ := http.NewRequest("PUT", ts.URL+"/api/v1/config", body)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var data map[string]any
	json.NewDecoder(resp.Body).Decode(&data)
	if data["message"] != "Configuration update received" {
		t.Errorf("unexpected message: %v", data["message"])
	}
}

func TestUpdateConfig_InvalidJSON(t *testing.T) {
	d := testDashboard(t, "")
	ts := httptest.NewServer(d.Handler())
	defer ts.Close()

	body := strings.NewReader(`{invalid json}`)
	req, _ := http.NewRequest("PUT", ts.URL+"/api/v1/config", body)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid JSON, got %d", resp.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// Events with filters
// ---------------------------------------------------------------------------

func TestGetEvents_WithFilters(t *testing.T) {
	d := testDashboard(t, "")
	ts := httptest.NewServer(d.Handler())
	defer ts.Close()

	// Test with min_score, since, until, action, client_ip, path, sort_by, sort_order
	resp, err := http.Get(ts.URL + "/api/v1/events?min_score=10&action=block&client_ip=1.2.3.4&path=/api&sort_by=score&sort_order=desc&since=2024-01-01T00:00:00Z&until=2025-01-01T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var data map[string]any
	json.NewDecoder(resp.Body).Decode(&data)
	if _, ok := data["events"]; !ok {
		t.Error("missing 'events' field")
	}
}

func TestGetEvents_InvalidLimitAndOffset(t *testing.T) {
	d := testDashboard(t, "")
	ts := httptest.NewServer(d.Handler())
	defer ts.Close()

	// Invalid limit/offset values should fall back to defaults
	resp, err := http.Get(ts.URL + "/api/v1/events?limit=abc&offset=xyz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var data map[string]any
	json.NewDecoder(resp.Body).Decode(&data)
	// defaults: limit=50, offset=0
	if int(data["limit"].(float64)) != 50 {
		t.Errorf("expected default limit 50, got %v", data["limit"])
	}
	if int(data["offset"].(float64)) != 0 {
		t.Errorf("expected default offset 0, got %v", data["offset"])
	}
}

func TestGetEvents_LargeLimitCapped(t *testing.T) {
	d := testDashboard(t, "")
	ts := httptest.NewServer(d.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/v1/events?limit=5000")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var data map[string]any
	json.NewDecoder(resp.Body).Decode(&data)
	if int(data["limit"].(float64)) != 1000 {
		t.Errorf("expected capped limit 1000, got %v", data["limit"])
	}
}

func TestGetEvent_EmptyID(t *testing.T) {
	d := testDashboard(t, "")
	ts := httptest.NewServer(d.Handler())
	defer ts.Close()

	// Path value extraction: request with valid but non-existent ID
	resp, err := http.Get(ts.URL + "/api/v1/events/some-id")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// Blacklist CRUD
// ---------------------------------------------------------------------------

func TestBlacklistCRUD(t *testing.T) {
	d := testDashboard(t, "")
	ts := httptest.NewServer(d.Handler())
	defer ts.Close()

	// List (empty)
	resp, err := http.Get(ts.URL + "/api/v1/rules/blacklist")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list: expected 200, got %d", resp.StatusCode)
	}

	// Add
	body := strings.NewReader(`{"value":"10.0.0.0/8","reason":"suspicious"}`)
	resp, err = http.Post(ts.URL+"/api/v1/rules/blacklist", "application/json", body)
	if err != nil {
		t.Fatal(err)
	}
	var entry RuleEntry
	json.NewDecoder(resp.Body).Decode(&entry)
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("add: expected 201, got %d", resp.StatusCode)
	}
	if entry.ID == "" {
		t.Fatal("add: expected non-empty ID")
	}
	if entry.Value != "10.0.0.0/8" {
		t.Errorf("expected value '10.0.0.0/8', got %q", entry.Value)
	}

	// List (should have one)
	resp, err = http.Get(ts.URL + "/api/v1/rules/blacklist")
	if err != nil {
		t.Fatal(err)
	}
	var listResp map[string]any
	json.NewDecoder(resp.Body).Decode(&listResp)
	resp.Body.Close()
	rules := listResp["rules"].([]any)
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}

	// Delete
	req, _ := http.NewRequest("DELETE", ts.URL+"/api/v1/rules/blacklist/"+entry.ID, nil)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("delete: expected 200, got %d", resp.StatusCode)
	}

	// Delete non-existent
	req, _ = http.NewRequest("DELETE", ts.URL+"/api/v1/rules/blacklist/999", nil)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("delete non-existent: expected 404, got %d", resp.StatusCode)
	}
}

func TestBlacklistAdd_InvalidJSON(t *testing.T) {
	d := testDashboard(t, "")
	ts := httptest.NewServer(d.Handler())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/api/v1/rules/blacklist", "application/json", strings.NewReader("not json"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid JSON, got %d", resp.StatusCode)
	}
}

func TestBlacklistAdd_MissingValue(t *testing.T) {
	d := testDashboard(t, "")
	ts := httptest.NewServer(d.Handler())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/api/v1/rules/blacklist", "application/json", strings.NewReader(`{"reason":"test"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing value, got %d", resp.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// RateLimit CRUD
// ---------------------------------------------------------------------------

func TestRateLimitCRUD(t *testing.T) {
	d := testDashboard(t, "")
	ts := httptest.NewServer(d.Handler())
	defer ts.Close()

	// List (empty)
	resp, err := http.Get(ts.URL + "/api/v1/rules/ratelimit")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list: expected 200, got %d", resp.StatusCode)
	}

	// Add
	body := strings.NewReader(`{"path":"/api","limit":100,"window":"1m","action":"block"}`)
	resp, err = http.Post(ts.URL+"/api/v1/rules/ratelimit", "application/json", body)
	if err != nil {
		t.Fatal(err)
	}
	var entry RateLimitEntry
	json.NewDecoder(resp.Body).Decode(&entry)
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("add: expected 201, got %d", resp.StatusCode)
	}
	if entry.ID == "" {
		t.Fatal("add: expected non-empty ID")
	}
	if entry.Limit != 100 {
		t.Errorf("expected limit 100, got %d", entry.Limit)
	}

	// Delete
	req, _ := http.NewRequest("DELETE", ts.URL+"/api/v1/rules/ratelimit/"+entry.ID, nil)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("delete: expected 200, got %d", resp.StatusCode)
	}

	// Delete non-existent
	req, _ = http.NewRequest("DELETE", ts.URL+"/api/v1/rules/ratelimit/999", nil)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("delete non-existent: expected 404, got %d", resp.StatusCode)
	}
}

func TestRateLimitAdd_InvalidJSON(t *testing.T) {
	d := testDashboard(t, "")
	ts := httptest.NewServer(d.Handler())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/api/v1/rules/ratelimit", "application/json", strings.NewReader("not json"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid JSON, got %d", resp.StatusCode)
	}
}

func TestRateLimitAdd_InvalidLimit(t *testing.T) {
	d := testDashboard(t, "")
	ts := httptest.NewServer(d.Handler())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/api/v1/rules/ratelimit", "application/json", strings.NewReader(`{"path":"/api","limit":0}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for zero limit, got %d", resp.StatusCode)
	}
}

func TestRateLimitAdd_NegativeLimit(t *testing.T) {
	d := testDashboard(t, "")
	ts := httptest.NewServer(d.Handler())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/api/v1/rules/ratelimit", "application/json", strings.NewReader(`{"path":"/api","limit":-5}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for negative limit, got %d", resp.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// Exclusions CRUD
// ---------------------------------------------------------------------------

func TestExclusionsCRUD(t *testing.T) {
	d := testDashboard(t, "")
	ts := httptest.NewServer(d.Handler())
	defer ts.Close()

	// List (empty)
	resp, err := http.Get(ts.URL + "/api/v1/rules/exclusions")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list: expected 200, got %d", resp.StatusCode)
	}

	// Add
	body := strings.NewReader(`{"path":"/health","detectors":["sqli","xss"],"reason":"false positive"}`)
	resp, err = http.Post(ts.URL+"/api/v1/rules/exclusions", "application/json", body)
	if err != nil {
		t.Fatal(err)
	}
	var entry ExclusionEntry
	json.NewDecoder(resp.Body).Decode(&entry)
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("add: expected 201, got %d", resp.StatusCode)
	}
	if entry.ID == "" {
		t.Fatal("add: expected non-empty ID")
	}
	if entry.Path != "/health" {
		t.Errorf("expected path '/health', got %q", entry.Path)
	}
	if len(entry.Detectors) != 2 {
		t.Errorf("expected 2 detectors, got %d", len(entry.Detectors))
	}

	// Delete
	req, _ := http.NewRequest("DELETE", ts.URL+"/api/v1/rules/exclusions/"+entry.ID, nil)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("delete: expected 200, got %d", resp.StatusCode)
	}

	// Delete non-existent
	req, _ = http.NewRequest("DELETE", ts.URL+"/api/v1/rules/exclusions/999", nil)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("delete non-existent: expected 404, got %d", resp.StatusCode)
	}
}

func TestExclusionAdd_InvalidJSON(t *testing.T) {
	d := testDashboard(t, "")
	ts := httptest.NewServer(d.Handler())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/api/v1/rules/exclusions", "application/json", strings.NewReader("not json"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid JSON, got %d", resp.StatusCode)
	}
}

func TestExclusionAdd_MissingPath(t *testing.T) {
	d := testDashboard(t, "")
	ts := httptest.NewServer(d.Handler())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/api/v1/rules/exclusions", "application/json", strings.NewReader(`{"detectors":["sqli"]}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing path, got %d", resp.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// Whitelist add error cases
// ---------------------------------------------------------------------------

func TestWhitelistAdd_InvalidJSON(t *testing.T) {
	d := testDashboard(t, "")
	ts := httptest.NewServer(d.Handler())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/api/v1/rules/whitelist", "application/json", strings.NewReader("not json"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid JSON, got %d", resp.StatusCode)
	}
}

func TestWhitelistAdd_MissingValue(t *testing.T) {
	d := testDashboard(t, "")
	ts := httptest.NewServer(d.Handler())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/api/v1/rules/whitelist", "application/json", strings.NewReader(`{"reason":"test"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing value, got %d", resp.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// SSE Broadcaster edge cases
// ---------------------------------------------------------------------------

func TestSSEBroadcasterDropsWhenFull(t *testing.T) {
	b := NewSSEBroadcaster()

	// Create a client with buffer of 1
	ch := make(chan string, 1)
	b.addClient(ch)

	// Fill the buffer
	b.Broadcast("evt1", `{"n":1}`)
	// Second broadcast should be dropped silently
	b.Broadcast("evt2", `{"n":2}`)

	msg := <-ch
	if !strings.Contains(msg, "evt1") {
		t.Errorf("expected first event, got %q", msg)
	}

	// Channel should be empty now (second was dropped)
	select {
	case m := <-ch:
		t.Errorf("expected no more messages, got %q", m)
	default:
		// expected
	}

	b.removeClient(ch)
}

func TestSSEBroadcasterMultipleClients(t *testing.T) {
	b := NewSSEBroadcaster()

	channels := make([]chan string, 5)
	for i := range channels {
		channels[i] = make(chan string, 64)
		b.addClient(channels[i])
	}

	if b.ClientCount() != 5 {
		t.Fatalf("expected 5 clients, got %d", b.ClientCount())
	}

	b.Broadcast("multi", `{"all":true}`)

	for i, ch := range channels {
		msg := <-ch
		if !strings.Contains(msg, "multi") {
			t.Errorf("client %d: expected 'multi' event, got %q", i, msg)
		}
	}

	for _, ch := range channels {
		b.removeClient(ch)
	}

	if b.ClientCount() != 0 {
		t.Fatalf("expected 0 clients, got %d", b.ClientCount())
	}
}

// ---------------------------------------------------------------------------
// Dashboard SSE() and API() accessors
// ---------------------------------------------------------------------------

func TestDashboardSSEAccessor(t *testing.T) {
	d := testDashboard(t, "")
	sse := d.SSE()
	if sse == nil {
		t.Fatal("expected non-nil SSE broadcaster")
	}
}

func TestDashboardAPIAccessor(t *testing.T) {
	d := testDashboard(t, "")
	api := d.API()
	if api == nil {
		t.Fatal("expected non-nil API")
	}
}

// ---------------------------------------------------------------------------
// actionString
// ---------------------------------------------------------------------------

func TestActionString(t *testing.T) {
	tests := []struct {
		action   engine.Action
		expected string
	}{
		{engine.ActionPass, "pass"},
		{engine.ActionBlock, "block"},
		{engine.ActionLog, "log"},
		{engine.ActionChallenge, "challenge"},
	}

	for _, tt := range tests {
		got := actionString(tt.action)
		if got != tt.expected {
			t.Errorf("actionString(%v) = %q, want %q", tt.action, got, tt.expected)
		}
	}
}

// ---------------------------------------------------------------------------
// SSE HandleSSE - not flusher
// ---------------------------------------------------------------------------

func TestSSEHandleSSE_NoFlusher(t *testing.T) {
	b := NewSSEBroadcaster()

	// Use a minimal ResponseWriter that doesn't implement http.Flusher
	w := &noFlushWriter{header: http.Header{}, code: 0}
	r := httptest.NewRequest("GET", "/sse", nil)

	b.HandleSSE(w, r)

	if w.code != http.StatusInternalServerError {
		t.Errorf("expected 500 when flusher not supported, got %d", w.code)
	}
}

// noFlushWriter is an http.ResponseWriter that does NOT implement http.Flusher.
type noFlushWriter struct {
	header http.Header
	code   int
	body   []byte
}

func (w *noFlushWriter) Header() http.Header         { return w.header }
func (w *noFlushWriter) WriteHeader(code int)         { w.code = code }
func (w *noFlushWriter) Write(b []byte) (int, error)  { w.body = append(w.body, b...); return len(b), nil }

// ---------------------------------------------------------------------------
// Static file - index.html path
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// SSE HandleSSE - message delivery through context cancellation
// ---------------------------------------------------------------------------

func TestSSEHandleSSE_MessageAndCancel(t *testing.T) {
	b := NewSSEBroadcaster()

	// Use httptest server to get a proper flusher
	ts := httptest.NewServer(http.HandlerFunc(b.HandleSSE))
	defer ts.Close()

	resp, err := http.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	// Read the initial connection message
	buf := make([]byte, 512)
	n, _ := resp.Body.Read(buf)
	initial := string(buf[:n])
	if !strings.Contains(initial, "connected") {
		t.Errorf("expected initial 'connected' event, got %q", initial)
	}

	// Send a broadcast message
	b.Broadcast("update", `{"key":"value"}`)

	// Read the broadcast message
	n, _ = resp.Body.Read(buf)
	msg := string(buf[:n])
	if !strings.Contains(msg, "update") {
		t.Errorf("expected 'update' event, got %q", msg)
	}

	// Close the response body to trigger context cancellation on the server side
	resp.Body.Close()
}

// ---------------------------------------------------------------------------
// Events Query error path
// ---------------------------------------------------------------------------

// errorEventStore returns an error from Query to cover the error path.
type errorEventStore struct {
	events.EventStore
}

func (e *errorEventStore) Store(_ engine.Event) error                               { return nil }
func (e *errorEventStore) Query(_ events.EventFilter) ([]engine.Event, int, error)  { return nil, 0, fmt.Errorf("query failed") }
func (e *errorEventStore) Get(_ string) (*engine.Event, error)                      { return nil, fmt.Errorf("not found") }
func (e *errorEventStore) Recent(_ int) ([]engine.Event, error)                     { return nil, nil }
func (e *errorEventStore) Count(_ events.EventFilter) (int, error)                  { return 0, nil }
func (e *errorEventStore) Close() error                                             { return nil }

func TestGetEvents_QueryError(t *testing.T) {
	eng := testEngine(t)
	store := &errorEventStore{}
	d := NewDashboard(eng, store, "")
	ts := httptest.NewServer(d.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/v1/events")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("expected 500 for query error, got %d", resp.StatusCode)
	}
}

func TestServeIndexHTML(t *testing.T) {
	d := testDashboard(t, "")
	ts := httptest.NewServer(d.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/index.html")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Errorf("expected text/html, got %q", ct)
	}
}
