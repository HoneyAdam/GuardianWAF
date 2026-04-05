package grpc

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
)

func TestDefaultConfig(t *testing.T) {
	cfg := &config.GRPCConfig{
		Enabled:              true,
		ReflectionEnabled:    true,
		MaxMessageSize:       4 * 1024 * 1024,
		MaxStreamDuration:    30 * time.Minute,
		MaxConcurrentStreams: 100,
	}

	if !cfg.Enabled {
		t.Error("expected gRPC to be enabled")
	}

	if !cfg.ReflectionEnabled {
		t.Error("expected reflection to be enabled")
	}

	if cfg.MaxMessageSize != 4*1024*1024 {
		t.Errorf("max_message_size = %d, want %d", cfg.MaxMessageSize, 4*1024*1024)
	}
}

func TestNewSecurity(t *testing.T) {
	cfg := &config.GRPCConfig{
		Enabled: true,
	}

	security, err := NewSecurity(cfg)
	if err != nil {
		t.Fatalf("NewSecurity failed: %v", err)
	}
	defer security.Stop()

	if security == nil {
		t.Fatal("expected security, got nil")
	}
}

func TestIsGRPCRequest(t *testing.T) {
	tests := []struct {
		contentType string
		expected    bool
	}{
		{"application/grpc", true},
		{"application/grpc+proto", true},
		{"application/grpc-web", true},
		{"application/grpc-web-text", true},
		{"application/json", false},
		{"text/plain", false},
		{"", false},
	}

	for _, tt := range tests {
		req := &http.Request{
			Header: http.Header{},
		}
		if tt.contentType != "" {
			req.Header.Set("Content-Type", tt.contentType)
		}

		result := IsGRPCRequest(req)
		if result != tt.expected {
			t.Errorf("IsGRPCRequest(contentType=%s) = %v, want %v",
				tt.contentType, result, tt.expected)
		}
	}
}

func TestParseMethod(t *testing.T) {
	tests := []struct {
		path           string
		expectedSvc    string
		expectedMethod string
		wantErr        bool
	}{
		{"/helloworld.Greeter/SayHello", "helloworld.Greeter", "SayHello", false},
		{"/package.Service/Method", "package.Service", "Method", false},
		{"/myapp.v1.UserService/GetUser", "myapp.v1.UserService", "GetUser", false},
		{"invalid", "", "", true},
		{"/", "", "", true},
		{"/only-service", "", "", true},
	}

	for _, tt := range tests {
		svc, method, err := ParseMethod(tt.path)
		if (err != nil) != tt.wantErr {
			t.Errorf("ParseMethod(%s) error = %v, wantErr %v", tt.path, err, tt.wantErr)
			continue
		}
		if !tt.wantErr {
			if svc != tt.expectedSvc {
				t.Errorf("ParseMethod(%s) service = %s, want %s", tt.path, svc, tt.expectedSvc)
			}
			if method != tt.expectedMethod {
				t.Errorf("ParseMethod(%s) method = %s, want %s", tt.path, method, tt.expectedMethod)
			}
		}
	}
}

func TestIsStreamingMethod(t *testing.T) {
	tests := []struct {
		method         string
		clientStream   bool
		serverStream   bool
	}{
		{"StreamData", true, true},
		{"SubscribeUpdates", false, true},
		{"WatchChanges", false, true},
		{"GetUser", false, false},
		{"CreateOrder", false, false},
		{"streamRecords", true, true},
	}

	for _, tt := range tests {
		client, server := IsStreamingMethod(tt.method)
		if client != tt.clientStream {
			t.Errorf("IsStreamingMethod(%s) clientStream = %v, want %v",
				tt.method, client, tt.clientStream)
		}
		if server != tt.serverStream {
			t.Errorf("IsStreamingMethod(%s) serverStream = %v, want %v",
				tt.method, server, tt.serverStream)
		}
	}
}

func TestRateLimiter(t *testing.T) {
	rl := NewRateLimiter(10, 5)

	// Should allow 5 burst requests
	for i := 0; i < 5; i++ {
		if !rl.Allow() {
			t.Errorf("request %d should be allowed", i+1)
		}
	}

	// 6th request should be denied
	if rl.Allow() {
		t.Error("6th request should be denied")
	}

	// Wait for tokens to refill
	time.Sleep(200 * time.Millisecond)
	if !rl.Allow() {
		t.Error("request after wait should be allowed")
	}
}

func TestIsAllowedService(t *testing.T) {
	cfg := &config.GRPCConfig{
		AllowedServices: []string{"helloworld.Greeter", "myapp.*"},
	}

	security, _ := NewSecurity(cfg)
	defer security.Stop()

	tests := []struct {
		service  string
		expected bool
	}{
		{"helloworld.Greeter", true},
		{"myapp.UserService", true},
		{"myapp.v1.OrderService", true},
		{"other.Service", false},
	}

	for _, tt := range tests {
		result := security.IsAllowedService(tt.service)
		if result != tt.expected {
			t.Errorf("IsAllowedService(%s) = %v, want %v", tt.service, result, tt.expected)
		}
	}
}

func TestIsBlockedService(t *testing.T) {
	cfg := &config.GRPCConfig{
		BlockedServices: []string{"admin.*", "internal.Debug"},
	}

	security, _ := NewSecurity(cfg)
	defer security.Stop()

	tests := []struct {
		service  string
		expected bool
	}{
		{"admin.UserService", true},
		{"admin.v1.ConfigService", true},
		{"internal.Debug", true},
		{"helloworld.Greeter", false},
	}

	for _, tt := range tests {
		result := security.IsBlockedService(tt.service)
		if result != tt.expected {
			t.Errorf("IsBlockedService(%s) = %v, want %v", tt.service, result, tt.expected)
		}
	}
}

func TestIsAllowedMethod(t *testing.T) {
	cfg := &config.GRPCConfig{
		AllowedMethods: []string{"helloworld.Greeter/SayHello", "*"},
	}

	security, _ := NewSecurity(cfg)
	defer security.Stop()

	tests := []struct {
		method   string
		expected bool
	}{
		{"helloworld.Greeter/SayHello", true},
		{"other.Service/Method", true},
	}

	for _, tt := range tests {
		result := security.IsAllowedMethod(tt.method)
		if result != tt.expected {
			t.Errorf("IsAllowedMethod(%s) = %v, want %v", tt.method, result, tt.expected)
		}
	}
}

func TestIsBlockedMethod(t *testing.T) {
	cfg := &config.GRPCConfig{
		BlockedMethods: []string{"admin.Service/DeleteAll"},
	}

	security, _ := NewSecurity(cfg)
	defer security.Stop()

	if !security.IsBlockedMethod("admin.Service/DeleteAll") {
		t.Error("should block admin.Service/DeleteAll")
	}

	if security.IsBlockedMethod("other.Service/Method") {
		t.Error("should not block other methods")
	}
}

func TestRegisterStream(t *testing.T) {
	cfg := &config.GRPCConfig{
		Enabled:              true,
		MaxConcurrentStreams: 2,
	}

	security, _ := NewSecurity(cfg)
	defer security.Stop()

	// Register first stream
	stream1 := security.RegisterStream(1, "helloworld.Greeter", "SayHello", false, false)
	if stream1 == nil {
		t.Fatal("expected stream1 to be registered")
	}

	// Register second stream
	stream2 := security.RegisterStream(2, "helloworld.Greeter", "SayHello", false, false)
	if stream2 == nil {
		t.Fatal("expected stream2 to be registered")
	}

	// Third stream should fail (max concurrent = 2)
	stream3 := security.RegisterStream(3, "helloworld.Greeter", "SayHello", false, false)
	if stream3 != nil {
		t.Error("expected stream3 to be rejected (max concurrent reached)")
	}

	// Verify streams
	if security.GetStreamCount() != 2 {
		t.Errorf("stream count = %d, want 2", security.GetStreamCount())
	}

	// Unregister and verify
	security.UnregisterStream(1)
	if security.GetStreamCount() != 1 {
		t.Errorf("stream count after unregister = %d, want 1", security.GetStreamCount())
	}
}

func TestGetStreamCountForService(t *testing.T) {
	cfg := &config.GRPCConfig{Enabled: true}
	security, _ := NewSecurity(cfg)
	defer security.Stop()

	security.RegisterStream(1, "ServiceA", "Method1", false, false)
	security.RegisterStream(2, "ServiceA", "Method2", false, false)
	security.RegisterStream(3, "ServiceB", "Method1", false, false)

	if count := security.GetStreamCountForService("ServiceA"); count != 2 {
		t.Errorf("ServiceA stream count = %d, want 2", count)
	}

	if count := security.GetStreamCountForService("ServiceB"); count != 1 {
		t.Errorf("ServiceB stream count = %d, want 1", count)
	}

	if count := security.GetStreamCountForService("ServiceC"); count != 0 {
		t.Errorf("ServiceC stream count = %d, want 0", count)
	}
}

func TestValidateRequest(t *testing.T) {
	cfg := &config.GRPCConfig{
		Enabled:         true,
		AllowedServices: []string{"helloworld.Greeter"},
		BlockedMethods:  []string{"helloworld.Greeter/AdminMethod"},
		MaxMessageSize:  1024,
	}

	security, _ := NewSecurity(cfg)
	defer security.Stop()

	tests := []struct {
		name      string
		path      string
		contentLength int64
		wantErr   bool
	}{
		{"valid request", "/helloworld.Greeter/SayHello", 100, false},
		{"blocked service", "/other.Service/Method", 100, true},
		{"blocked method", "/helloworld.Greeter/AdminMethod", 100, true},
		{"message too large", "/helloworld.Greeter/SayHello", 2048, true},
		{"invalid path", "/invalid", 100, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &http.Request{
				URL: &url.URL{},
				Header: http.Header{
					"Content-Type": []string{"application/grpc"},
				},
			}
			req.URL.Path = tt.path
			req.ContentLength = tt.contentLength

			err := security.ValidateRequest(req)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateRequest() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestParseGRPCTimeout(t *testing.T) {
	tests := []struct {
		input    string
		expected time.Duration
		wantErr  bool
	}{
		{"10S", 10 * time.Second, false},
		{"5M", 5 * time.Minute, false},
		{"1H", time.Hour, false},
		{"500m", 500 * time.Millisecond, false},
		{"1000u", 1000 * time.Microsecond, false},
		{"1000000n", time.Millisecond, false},
		{"invalid", 0, true},
		{"", 0, true},
		{"10X", 0, true},
	}

	for _, tt := range tests {
		result, err := parseGRPCTimeout(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("parseGRPCTimeout(%s) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			continue
		}
		if !tt.wantErr && result != tt.expected {
			t.Errorf("parseGRPCTimeout(%s) = %v, want %v", tt.input, result, tt.expected)
		}
	}
}

func TestGetRequestInfo(t *testing.T) {
	req := &http.Request{
		URL:    &url.URL{},
		Header: make(http.Header),
	}
	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Set("grpc-message-type", "helloworld.HelloRequest")
	req.Header.Set("grpc-timeout", "30S")
	req.Header.Set(":authority", "localhost:50051")
	req.URL.Path = "/helloworld.Greeter/SayHello"

	info := GetRequestInfo(req)

	if info.Service != "helloworld.Greeter" {
		t.Errorf("Service = %s, want helloworld.Greeter", info.Service)
	}

	if info.Method != "SayHello" {
		t.Errorf("Method = %s, want SayHello", info.Method)
	}

	if info.MessageType != "helloworld.HelloRequest" {
		t.Errorf("MessageType = %s, want helloworld.HelloRequest", info.MessageType)
	}

	if info.Timeout != 30*time.Second {
		t.Errorf("Timeout = %v, want 30s", info.Timeout)
	}

	if info.Authority != "localhost:50051" {
		t.Errorf("Authority = %s, want localhost:50051", info.Authority)
	}
}

func TestCreateGRPCErrorResponse(t *testing.T) {
	resp := CreateGRPCErrorResponse(StatusPermissionDenied, "access denied")

	if resp.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	if resp.Header.Get("grpc-status") != "7" {
		t.Errorf("grpc-status = %s, want 7", resp.Header.Get("grpc-status"))
	}

	if !strings.Contains(resp.Header.Get("grpc-message"), "access") {
		t.Errorf("grpc-message should contain 'access', got %s", resp.Header.Get("grpc-message"))
	}
}

func TestIsGRPCWebRequest(t *testing.T) {
	tests := []struct {
		contentType string
		expected    bool
	}{
		{"application/grpc-web", true},
		{"application/grpc-web-text", true},
		{"application/grpc", false},
		{"application/json", false},
	}

	for _, tt := range tests {
		req := &http.Request{
			Header: http.Header{},
		}
		req.Header.Set("Content-Type", tt.contentType)

		result := IsGRPCWebRequest(req)
		if result != tt.expected {
			t.Errorf("IsGRPCWebRequest(%s) = %v, want %v", tt.contentType, result, tt.expected)
		}
	}
}

func TestLayer_NewLayer(t *testing.T) {
	cfg := &config.GRPCConfig{Enabled: false}

	layer, err := NewLayer(cfg)
	if err != nil {
		t.Fatalf("NewLayer failed: %v", err)
	}

	if layer.security != nil {
		t.Error("security should be nil when disabled")
	}

	if layer.Name() != "grpc" {
		t.Errorf("name = %s, want grpc", layer.Name())
	}
}

func TestLayer_Process_NotGRPC(t *testing.T) {
	cfg := &config.GRPCConfig{Enabled: true}

	layer, err := NewLayer(cfg)
	if err != nil {
		t.Fatalf("NewLayer failed: %v", err)
	}
	defer layer.Stop()

	// Regular HTTP request (not gRPC)
	req := &http.Request{
		Method: "GET",
		URL:    &url.URL{},
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
	}
	req.URL.Path = "/api/test"

	ctx := &engine.RequestContext{
		Request: req,
	}

	result := layer.Process(ctx)

	if result.Action != engine.ActionPass {
		t.Errorf("action = %v, want pass", result.Action)
	}
}

func TestLayer_Process_BlockedService(t *testing.T) {
	cfg := &config.GRPCConfig{
		Enabled:         true,
		BlockedServices: []string{"admin.*"},
	}

	layer, err := NewLayer(cfg)
	if err != nil {
		t.Fatalf("NewLayer failed: %v", err)
	}
	defer layer.Stop()

	req := &http.Request{
		URL: &url.URL{},
		Header: http.Header{
			"Content-Type": []string{"application/grpc"},
		},
	}
	req.URL.Path = "/admin.Service/DeleteAll"

	ctx := &engine.RequestContext{
		Request: req,
	}

	result := layer.Process(ctx)

	if result.Action != engine.ActionBlock {
		t.Errorf("action = %v, want block", result.Action)
	}

	if len(result.Findings) == 0 {
		t.Error("should have findings for blocked request")
	}
}

func TestLayer_Process_ValidGRPC(t *testing.T) {
	cfg := &config.GRPCConfig{
		Enabled: true,
	}

	layer, err := NewLayer(cfg)
	if err != nil {
		t.Fatalf("NewLayer failed: %v", err)
	}
	defer layer.Stop()

	req := &http.Request{
		URL: &url.URL{},
		Header: http.Header{
			"Content-Type": []string{"application/grpc"},
		},
	}
	req.URL.Path = "/helloworld.Greeter/SayHello"

	ctx := &engine.RequestContext{
		Request: req,
	}

	result := layer.Process(ctx)

	if result.Action != engine.ActionPass {
		t.Errorf("action = %v, want pass", result.Action)
	}
}

func TestHandler_Stats(t *testing.T) {
	cfg := &config.GRPCConfig{Enabled: true}
	security, _ := NewSecurity(cfg)
	defer security.Stop()

	handler := NewHandler(security)

	// Register a stream
	security.RegisterStream(1, "test.Service", "Method", false, false)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/grpc/stats", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var stats Stats
	if err := json.Unmarshal(w.Body.Bytes(), &stats); err != nil {
		t.Fatalf("failed to unmarshal stats: %v", err)
	}

	if stats.ActiveStreams != 1 {
		t.Errorf("active_streams = %d, want 1", stats.ActiveStreams)
	}
}

func TestHandler_Streams(t *testing.T) {
	cfg := &config.GRPCConfig{Enabled: true}
	security, _ := NewSecurity(cfg)
	defer security.Stop()

	handler := NewHandler(security)

	// Register streams
	security.RegisterStream(1, "ServiceA", "Method1", true, false)
	security.RegisterStream(2, "ServiceB", "Method2", false, true)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/grpc/streams", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var result map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	streams, ok := result["streams"].([]any)
	if !ok {
		t.Fatal("expected streams array")
	}

	if len(streams) != 2 {
		t.Errorf("stream count = %d, want 2", len(streams))
	}
}

func TestHandler_Services(t *testing.T) {
	cfg := &config.GRPCConfig{
		Enabled:         true,
		AllowedServices: []string{"AllowedService"},
	}
	security, _ := NewSecurity(cfg)
	defer security.Stop()

	handler := NewHandler(security)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/grpc/services", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestFrame_IsHeaders(t *testing.T) {
	tests := []struct {
		frameType uint8
		expected  bool
	}{
		{FrameHeaders, true},
		{FrameData, false},
		{FrameSettings, false},
	}

	for _, tt := range tests {
		frame := &Frame{Type: tt.frameType}
		if result := frame.IsHeaders(); result != tt.expected {
			t.Errorf("IsHeaders(type=%d) = %v, want %v", tt.frameType, result, tt.expected)
		}
	}
}

func TestFrame_IsEndStream(t *testing.T) {
	frame := &Frame{Flags: 0x01}
	if !frame.IsEndStream() {
		t.Error("expected END_STREAM flag to be set")
	}

	frame.Flags = 0x00
	if frame.IsEndStream() {
		t.Error("expected END_STREAM flag to not be set")
	}
}

func TestParseHTTP2FrameHeader(t *testing.T) {
	// Frame header: 3 bytes length + 1 byte type + 1 byte flags + 4 bytes stream ID
	data := []byte{
		0x00, 0x00, 0x10, // Length: 16
		0x01,             // Type: HEADERS
		0x04,             // Flags: END_HEADERS
		0x00, 0x00, 0x00, 0x01, // Stream ID: 1
	}

	frame, err := ParseHTTP2FrameHeader(data)
	if err != nil {
		t.Fatalf("ParseHTTP2FrameHeader failed: %v", err)
	}

	if frame.Type != FrameHeaders {
		t.Errorf("Type = %d, want %d", frame.Type, FrameHeaders)
	}

	if frame.Flags != 0x04 {
		t.Errorf("Flags = %d, want 4", frame.Flags)
	}

	if frame.StreamID != 1 {
		t.Errorf("StreamID = %d, want 1", frame.StreamID)
	}

	if len(frame.Payload) != 16 {
		t.Errorf("Payload length = %d, want 16", len(frame.Payload))
	}
}

func TestParseHTTP2FrameHeader_TooShort(t *testing.T) {
	data := []byte{0x00, 0x00} // Too short

	_, err := ParseHTTP2FrameHeader(data)
	if err == nil {
		t.Error("expected error for short data")
	}
}

func TestReadHTTP2Preface(t *testing.T) {
	preface := []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
	reader := bytes.NewReader(preface)

	err := ReadHTTP2Preface(reader)
	if err != nil {
		t.Errorf("ReadHTTP2Preface failed: %v", err)
	}
}

func TestReadHTTP2Preface_Invalid(t *testing.T) {
	preface := []byte("INVALID PREFACE DATA HERE!!!")
	reader := bytes.NewReader(preface)

	err := ReadHTTP2Preface(reader)
	if err == nil {
		t.Error("expected error for invalid preface")
	}
}

func TestContextFunctions(t *testing.T) {
	ctx := context.Background()

	// Test with empty context
	if GetServiceFromContext(ctx) != "" {
		t.Error("expected empty service from empty context")
	}

	if GetMethodFromContext(ctx) != "" {
		t.Error("expected empty method from empty context")
	}

	if GetStreamFromContext(ctx) != nil {
		t.Error("expected nil stream from empty context")
	}

	// Test with values
	ctx = context.WithValue(ctx, ContextKeyService, "test.Service")
	ctx = context.WithValue(ctx, ContextKeyMethod, "TestMethod")

	if GetServiceFromContext(ctx) != "test.Service" {
		t.Error("expected service from context")
	}

	if GetMethodFromContext(ctx) != "TestMethod" {
		t.Error("expected method from context")
	}
}

func TestStream_UpdateActivity(t *testing.T) {
	stream := &Stream{
		StartTime:    time.Now(),
		LastActivity: time.Now().Add(-time.Hour),
	}

	oldActivity := stream.LastActivity
	stream.UpdateActivity()

	if !stream.LastActivity.After(oldActivity) {
		t.Error("expected LastActivity to be updated")
	}
}

func TestStream_MessageCounts(t *testing.T) {
	stream := &Stream{}

	stream.IncMessagesSent()
	stream.IncMessagesSent()
	stream.IncMessagesRecv()

	stream.mu.RLock()
	sent := stream.MessagesSent
	recv := stream.MessagesRecv
	stream.mu.RUnlock()

	if sent != 2 {
		t.Errorf("MessagesSent = %d, want 2", sent)
	}

	if recv != 1 {
		t.Errorf("MessagesRecv = %d, want 1", recv)
	}
}

func TestCleanupStaleStreams(t *testing.T) {
	cfg := &config.GRPCConfig{
		Enabled:           true,
		MaxStreamDuration: 100 * time.Millisecond,
	}

	security, _ := NewSecurity(cfg)
	defer security.Stop()

	// Register a stream
	stream := security.RegisterStream(1, "test.Service", "Method", false, false)
	if stream == nil {
		t.Fatal("expected stream to be registered")
	}

	// Set last activity to be old
	stream.mu.Lock()
	stream.LastActivity = time.Now().Add(-time.Hour)
	stream.mu.Unlock()

	// Trigger cleanup
	security.cleanupStaleStreams()

	// Stream should be cleaned up
	if security.GetStream(1) != nil {
		t.Error("expected stale stream to be cleaned up")
	}
}

func TestGetStats(t *testing.T) {
	cfg := &config.GRPCConfig{Enabled: true}
	security, _ := NewSecurity(cfg)
	defer security.Stop()

	// Register streams
	stream1 := security.RegisterStream(1, "ServiceA", "Method1", false, false)
	stream2 := security.RegisterStream(2, "ServiceA", "Method2", false, false)
	security.RegisterStream(3, "ServiceB", "Method1", false, false)

	// Simulate message counts
	stream1.IncMessagesSent()
	stream1.IncMessagesRecv()
	stream2.IncMessagesSent()

	stats := security.GetStats()

	if stats.ActiveStreams != 3 {
		t.Errorf("ActiveStreams = %d, want 3", stats.ActiveStreams)
	}

	if stats.StreamsByService["ServiceA"] != 2 {
		t.Errorf("ServiceA streams = %d, want 2", stats.StreamsByService["ServiceA"])
	}

	if stats.StreamsByService["ServiceB"] != 1 {
		t.Errorf("ServiceB streams = %d, want 1", stats.StreamsByService["ServiceB"])
	}
}
