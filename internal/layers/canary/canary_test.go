package canary

import (
	"net/http"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Enabled {
		t.Error("expected canary to be disabled by default")
	}

	if cfg.Strategy != StrategyPercentage {
		t.Errorf("strategy = %s, want percentage", cfg.Strategy)
	}

	if cfg.Percentage != 10 {
		t.Errorf("percentage = %d, want 10", cfg.Percentage)
	}

	if cfg.ErrorThreshold != 5.0 {
		t.Errorf("error_threshold = %f, want 5.0", cfg.ErrorThreshold)
	}

	if cfg.LatencyThreshold != 500*time.Millisecond {
		t.Errorf("latency_threshold = %v, want 500ms", cfg.LatencyThreshold)
	}
}

func TestConfigValidate(t *testing.T) {
	// Valid config
	cfg := &Config{
		Percentage:     50,
		ErrorThreshold: 10,
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("valid config should not error: %v", err)
	}

	// Invalid percentage
	cfg = &Config{Percentage: 150}
	if err := cfg.Validate(); err == nil {
		t.Error("percentage > 100 should error")
	}

	// Invalid error threshold
	cfg = &Config{Percentage: 50, ErrorThreshold: 150}
	if err := cfg.Validate(); err == nil {
		t.Error("error_threshold > 100 should error")
	}
}

func TestNew(t *testing.T) {
	cfg := &Config{
		Enabled:    true,
		Strategy:   StrategyPercentage,
		Percentage: 20,
	}

	canary, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	defer canary.Close()

	if canary == nil {
		t.Fatal("expected canary, got nil")
	}

	if !canary.stats.Healthy.Load() {
		t.Error("expected canary to be healthy initially")
	}
}

func TestShouldRouteToCanary_Disabled(t *testing.T) {
	cfg := &Config{Enabled: false}
	canary, _ := New(cfg)
	defer canary.Close()

	req, _ := http.NewRequest("GET", "http://example.com/test", nil)

	if canary.ShouldRouteToCanary(req) {
		t.Error("disabled canary should not route")
	}
}

func TestShouldRouteToCanary_Percentage(t *testing.T) {
	cfg := &Config{
		Enabled:    true,
		Strategy:   StrategyPercentage,
		Percentage: 100, // 100% to canary
	}
	canary, _ := New(cfg)
	defer canary.Close()

	req, _ := http.NewRequest("GET", "http://example.com/test", nil)
	req.Header.Set("X-Request-ID", "test-123")

	if !canary.ShouldRouteToCanary(req) {
		t.Error("100% should always route to canary")
	}

	// Test 0%
	cfg2 := &Config{
		Enabled:    true,
		Strategy:   StrategyPercentage,
		Percentage: 0,
	}
	canary2, _ := New(cfg2)
	defer canary2.Close()

	if canary2.ShouldRouteToCanary(req) {
		t.Error("0% should never route to canary")
	}
}

func TestShouldRouteToCanary_Header(t *testing.T) {
	cfg := &Config{
		Enabled:     true,
		Strategy:    StrategyHeader,
		HeaderName:  "X-Canary",
		HeaderValue: "true",
	}
	canary, _ := New(cfg)
	defer canary.Close()

	// Request with matching header
	req, _ := http.NewRequest("GET", "http://example.com/test", nil)
	req.Header.Set("X-Canary", "true")

	if !canary.ShouldRouteToCanary(req) {
		t.Error("request with canary header should route to canary")
	}

	// Request without header
	req2, _ := http.NewRequest("GET", "http://example.com/test", nil)

	if canary.ShouldRouteToCanary(req2) {
		t.Error("request without canary header should not route")
	}
}

func TestShouldRouteToCanary_Cookie(t *testing.T) {
	cfg := &Config{
		Enabled:     true,
		Strategy:    StrategyCookie,
		CookieName:  "canary",
		CookieValue: "yes",
	}
	canary, _ := New(cfg)
	defer canary.Close()

	// Request with matching cookie
	req, _ := http.NewRequest("GET", "http://example.com/test", nil)
	req.AddCookie(&http.Cookie{Name: "canary", Value: "yes"})

	if !canary.ShouldRouteToCanary(req) {
		t.Error("request with canary cookie should route to canary")
	}

	// Request without cookie
	req2, _ := http.NewRequest("GET", "http://example.com/test", nil)

	if canary.ShouldRouteToCanary(req2) {
		t.Error("request without canary cookie should not route")
	}
}

func TestShouldRouteToCanary_Random(t *testing.T) {
	cfg := &Config{
		Enabled:    true,
		Strategy:   StrategyRandom,
		Percentage: 50,
	}
	canary, _ := New(cfg)
	defer canary.Close()

	// Random should route approximately 50% of the time
	req, _ := http.NewRequest("GET", "http://example.com/test", nil)

	// Just verify it doesn't panic and returns a bool
	_ = canary.ShouldRouteToCanary(req)
}

func TestRecordResult(t *testing.T) {
	cfg := &Config{
		Enabled:    true,
		Percentage: 50,
	}
	canary, _ := New(cfg)
	defer canary.Close()

	// Record some results
	canary.RecordResult(true, 200, 100*time.Millisecond)
	canary.RecordResult(true, 200, 150*time.Millisecond)
	canary.RecordResult(true, 500, 200*time.Millisecond)
	canary.RecordResult(false, 200, 100*time.Millisecond)

	stats := canary.GetStats()

	if stats["total_requests"] != int64(4) {
		t.Errorf("total_requests = %v, want 4", stats["total_requests"])
	}

	if stats["canary_requests"] != int64(3) {
		t.Errorf("canary_requests = %v, want 3", stats["canary_requests"])
	}
}

func TestAutoRollback(t *testing.T) {
	cfg := &Config{
		Enabled:          true,
		Percentage:       50,
		AutoRollback:     true,
		ErrorThreshold:   10.0, // 10% error threshold
		LatencyThreshold: 1 * time.Second,
	}
	canary, _ := New(cfg)
	defer canary.Close()

	// Record many errors to trigger rollback
	for i := 0; i < 200; i++ {
		canary.RecordResult(true, 500, 50*time.Millisecond)
	}

	// Should be halted due to high error rate
	if !canary.IsHalted() {
		t.Error("canary should be halted due to high error rate")
	}

	if canary.ShouldRouteToCanary(nil) {
		t.Error("halted canary should not route")
	}
}

func TestHaltAndResume(t *testing.T) {
	cfg := &Config{Enabled: true}
	canary, _ := New(cfg)
	defer canary.Close()

	canary.Halt()

	if !canary.IsHalted() {
		t.Error("expected canary to be halted")
	}

	canary.Resume()

	if canary.IsHalted() {
		t.Error("expected canary to be resumed")
	}
}

func TestAdjustPercentage(t *testing.T) {
	cfg := &Config{Enabled: true, Percentage: 10}
	canary, _ := New(cfg)
	defer canary.Close()

	err := canary.AdjustPercentage(50)
	if err != nil {
		t.Fatalf("AdjustPercentage failed: %v", err)
	}

	if canary.config.Percentage != 50 {
		t.Errorf("percentage = %d, want 50", canary.config.Percentage)
	}

	// Invalid percentage
	err = canary.AdjustPercentage(150)
	if err == nil {
		t.Error("adjusting to 150% should error")
	}
}

func TestGetUpstream(t *testing.T) {
	cfg := &Config{
		Enabled:        true,
		Strategy:       StrategyPercentage,
		Percentage:     100,
		StableUpstream: "stable:8080",
		CanaryUpstream: "canary:8080",
	}
	canary, _ := New(cfg)
	defer canary.Close()

	req, _ := http.NewRequest("GET", "http://example.com/test", nil)

	upstream := canary.GetUpstream(req)
	if upstream != "canary:8080" {
		t.Errorf("upstream = %s, want canary:8080", upstream)
	}

	// With 0% canary
	cfg2 := &Config{
		Enabled:        true,
		Strategy:       StrategyPercentage,
		Percentage:     0,
		StableUpstream: "stable:8080",
		CanaryUpstream: "canary:8080",
	}
	canary2, _ := New(cfg2)
	defer canary2.Close()

	upstream = canary2.GetUpstream(req)
	if upstream != "stable:8080" {
		t.Errorf("upstream = %s, want stable:8080", upstream)
	}
}

func TestLayer_Name(t *testing.T) {
	layer, _ := NewLayer(&LayerConfig{Enabled: false})

	if layer.Name() != "canary" {
		t.Errorf("Name() = %s, want canary", layer.Name())
	}
}

func TestLayer_Order(t *testing.T) {
	layer, _ := NewLayer(&LayerConfig{Enabled: false})

	if layer.Order() != 95 {
		t.Errorf("Order() = %d, want 95", layer.Order())
	}
}

func TestLayer_Process_Disabled(t *testing.T) {
	layer, _ := NewLayer(&LayerConfig{Enabled: false})

	ctx := &engine.RequestContext{
		Method: "GET",
		Path:   "/test",
	}

	result := layer.Process(ctx)

	if result.Action != engine.ActionPass {
		t.Errorf("Action = %v, want Pass", result.Action)
	}
}

func TestMiddleware(t *testing.T) {
	cfg := &Config{
		Enabled:        true,
		Strategy:       StrategyPercentage,
		Percentage:     100,
		CanaryVersion:  "v2.0.0-beta",
		HeaderName:     "X-Canary",
	}
	canary, _ := New(cfg)
	defer canary.Close()

	middleware := NewMiddleware(canary)

	handlerCalled := false
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		// Check header was set
		if r.Header.Get("X-Canary-Version") != "v2.0.0-beta" {
			t.Error("X-Canary-Version header not set")
		}
	})

	wrapped := middleware.Handler(testHandler)

	req, _ := http.NewRequest("GET", "/test", nil)
	rr := &mockResponseWriter{}

	wrapped.ServeHTTP(rr, req)

	if !handlerCalled {
		t.Error("handler was not called")
	}
}

func TestRouter(t *testing.T) {
	cfg := &Config{
		Enabled:        true,
		Strategy:       StrategyPercentage,
		Percentage:     100,
		StableUpstream: "stable:8080",
		CanaryUpstream: "canary:8080",
	}
	c, _ := New(cfg)
	defer c.Close()

	router := NewRouter(c)

	req, _ := http.NewRequest("GET", "/test", nil)

	if !router.IsCanaryRequest(req) {
		t.Error("expected IsCanaryRequest to return true")
	}

	upstream := router.SelectUpstream(req)
	if upstream != "canary:8080" {
		t.Errorf("upstream = %s, want canary:8080", upstream)
	}
}

func TestFnv32a(t *testing.T) {
	// Test consistent hashing
	h1 := fnv32a("test-key")
	h2 := fnv32a("test-key")

	if h1 != h2 {
		t.Error("fnv32a should produce consistent hashes")
	}

	// Different keys should likely produce different hashes
	h3 := fnv32a("different-key")
	if h1 == h3 {
		t.Error("different keys should produce different hashes")
	}
}

// Mock ResponseWriter for testing
type mockResponseWriter struct {
	headers http.Header
	status  int
}

func (m *mockResponseWriter) Header() http.Header {
	if m.headers == nil {
		m.headers = make(http.Header)
	}
	return m.headers
}

func (m *mockResponseWriter) Write([]byte) (int, error) {
	return 0, nil
}

func (m *mockResponseWriter) WriteHeader(status int) {
	m.status = status
}
