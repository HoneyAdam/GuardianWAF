package websocket

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if !cfg.Enabled {
		t.Error("expected websocket to be enabled by default")
	}

	if cfg.MaxMessageSize != 10*1024*1024 {
		t.Errorf("max_message_size = %d, want %d", cfg.MaxMessageSize, 10*1024*1024)
	}

	if cfg.MaxFrameSize != 1*1024*1024 {
		t.Errorf("max_frame_size = %d, want %d", cfg.MaxFrameSize, 1*1024*1024)
	}

	if cfg.RateLimitPerSecond != 100 {
		t.Errorf("rate_limit_per_second = %d, want 100", cfg.RateLimitPerSecond)
	}

	if cfg.HandshakeTimeout != 10*time.Second {
		t.Errorf("handshake_timeout = %v, want 10s", cfg.HandshakeTimeout)
	}
}

func TestNewSecurity(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true

	security, err := NewSecurity(cfg)
	if err != nil {
		t.Fatalf("NewSecurity failed: %v", err)
	}
	defer security.Stop()

	if security == nil {
		t.Fatal("expected security, got nil")
	}

	if security.config != cfg {
		t.Error("config mismatch")
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

	// 6th request should be denied (no tokens left)
	if rl.Allow() {
		t.Error("6th request should be denied")
	}

	// Wait and try again
	time.Sleep(200 * time.Millisecond) // Wait for tokens to refill
	if !rl.Allow() {
		t.Error("request after wait should be allowed")
	}
}

func TestIsWebSocketUpgrade(t *testing.T) {
	tests := []struct {
		upgrade    string
		connection string
		expected   bool
	}{
		{"websocket", "Upgrade", true},
		{"websocket", "keep-alive, Upgrade", true},
		{"websocket", "keep-alive", false},
		{"WebSocket", "upgrade", true}, // Case insensitive
		{"", "Upgrade", false},
		{"websocket", "", false},
	}

	for _, tt := range tests {
		req := &http.Request{
			Header: http.Header{},
		}
		if tt.upgrade != "" {
			req.Header.Set("Upgrade", tt.upgrade)
		}
		if tt.connection != "" {
			req.Header.Set("Connection", tt.connection)
		}

		result := isWebSocketUpgrade(req)
		if result != tt.expected {
			t.Errorf("isWebSocketUpgrade(upgrade=%s, connection=%s) = %v, want %v",
				tt.upgrade, tt.connection, result, tt.expected)
		}
	}
}

func TestIsAllowedOrigin(t *testing.T) {
	cfg := &Config{
		AllowedOrigins: []string{
			"https://example.com",
			"https://*.example.com",
		},
	}

	security := &Security{config: cfg}

	tests := []struct {
		origin   string
		expected bool
	}{
		{"https://example.com", true},
		{"https://sub.example.com", true},
		{"https://deep.sub.example.com", true},
		{"https://other.com", false},
		{"http://example.com", false}, // Wrong protocol
		{"", false},
	}

	for _, tt := range tests {
		result := security.isAllowedOrigin(tt.origin)
		if result != tt.expected {
			t.Errorf("isAllowedOrigin(%s) = %v, want %v", tt.origin, result, tt.expected)
		}
	}
}

func TestIsAllowedOrigin_AllowAll(t *testing.T) {
	cfg := &Config{
		AllowedOrigins: []string{}, // Empty = allow all
	}

	security := &Security{config: cfg}

	if !security.isAllowedOrigin("https://any-origin.com") {
		t.Error("empty allowed_origins should allow all")
	}
}

func TestIsBlockedExtension(t *testing.T) {
	cfg := &Config{
		BlockedExtensions: []string{".exe", ".bat", ".cmd"},
	}

	security := &Security{config: cfg}

	tests := []struct {
		path     string
		expected bool
	}{
		{"/api/test.exe", true},
		{"/api/test.BAT", true}, // Case insensitive
		{"/api/test.cmd", true},
		{"/api/test.txt", false},
		{"/api/test", false},
		{"/exe/test", false}, // Not an extension
	}

	for _, tt := range tests {
		result := security.isBlockedExtension(tt.path)
		if result != tt.expected {
			t.Errorf("isBlockedExtension(%s) = %v, want %v", tt.path, result, tt.expected)
		}
	}
}

func TestGenerateAcceptKey(t *testing.T) {
	// Test with known WebSocket key
	key := "dGhlIHNhbXBsZSBub25jZQ=="
	hash := sha256.Sum256([]byte(key + websocketGUID))
	expected := base64.StdEncoding.EncodeToString(hash[:])

	result := GenerateAcceptKey(key)
	if result != expected {
		t.Errorf("GenerateAcceptKey returned unexpected result")
	}

	// Verify it's base64
	decoded, err := base64.StdEncoding.DecodeString(result)
	if err != nil {
		t.Error("result should be valid base64")
	}

	if len(decoded) != 32 { // SHA-256 is 32 bytes
		t.Errorf("decoded length = %d, want 32", len(decoded))
	}
}

func TestParseFrame(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected Frame
	}{
		{
			name:  "text frame",
			input: []byte{0x81, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f}, // "Hello"
			expected: Frame{
				Fin:        true,
				Opcode:     OpText,
				PayloadLen: 5,
				Payload:    []byte("Hello"),
			},
		},
		{
			name:  "binary frame",
			input: []byte{0x82, 0x03, 0x01, 0x02, 0x03},
			expected: Frame{
				Fin:        true,
				Opcode:     OpBinary,
				PayloadLen: 3,
				Payload:    []byte{0x01, 0x02, 0x03},
			},
		},
		{
			name:  "ping frame",
			input: []byte{0x89, 0x00}, // Ping with no payload
			expected: Frame{
				Fin:        true,
				Opcode:     OpPing,
				PayloadLen: 0,
			},
		},
		{
			name:  "continuation frame",
			input: []byte{0x00, 0x04, 0x74, 0x65, 0x73, 0x74}, // "test"
			expected: Frame{
				Fin:        false,
				Opcode:     OpContinuation,
				PayloadLen: 4,
				Payload:    []byte("test"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			frame, err := ParseFrame(bytes.NewReader(tt.input))
			if err != nil {
				t.Fatalf("ParseFrame failed: %v", err)
			}

			if frame.Fin != tt.expected.Fin {
				t.Errorf("Fin = %v, want %v", frame.Fin, tt.expected.Fin)
			}
			if frame.Opcode != tt.expected.Opcode {
				t.Errorf("Opcode = %d, want %d", frame.Opcode, tt.expected.Opcode)
			}
			if frame.PayloadLen != tt.expected.PayloadLen {
				t.Errorf("PayloadLen = %d, want %d", frame.PayloadLen, tt.expected.PayloadLen)
			}
			if !bytes.Equal(frame.Payload, tt.expected.Payload) {
				t.Errorf("Payload = %v, want %v", frame.Payload, tt.expected.Payload)
			}
		})
	}
}

func TestParseFrame_Masked(t *testing.T) {
	// Masked text frame "Hello" with mask key 0x37, 0xfa, 0x21, 0x3d
	// Payload: H(0x48)^0x37=0x7F, e(0x65)^0xFA=0x9F, l(0x6C)^0x21=0x4D, l(0x6C)^0x3D=0x51, o(0x6F)^0x37=0x58
	input := []byte{0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58}

	frame, err := ParseFrame(bytes.NewReader(input))
	if err != nil {
		t.Fatalf("ParseFrame failed: %v", err)
	}

	if !frame.Masked {
		t.Error("frame should be masked")
	}

	if !bytes.Equal(frame.Payload, []byte("Hello")) {
		t.Errorf("unmasked payload = %v, want Hello", frame.Payload)
	}
}

func TestWriteFrame(t *testing.T) {
	frame := &Frame{
		Fin:     true,
		Opcode:  OpText,
		Payload: []byte("Hello"),
	}

	var buf bytes.Buffer
	if err := WriteFrame(&buf, frame); err != nil {
		t.Fatalf("WriteFrame failed: %v", err)
	}

	// Read it back
	parsed, err := ParseFrame(&buf)
	if err != nil {
		t.Fatalf("ParseFrame failed: %v", err)
	}

	if parsed.Opcode != frame.Opcode {
		t.Errorf("Opcode = %d, want %d", parsed.Opcode, frame.Opcode)
	}

	if !bytes.Equal(parsed.Payload, frame.Payload) {
		t.Errorf("Payload = %v, want %v", parsed.Payload, frame.Payload)
	}
}

func TestIsValidUTF8(t *testing.T) {
	tests := []struct {
		data     []byte
		expected bool
	}{
		{[]byte("Hello"), true},
		{[]byte("こんにちは"), true},      // Japanese
		{[]byte("Привет"), true},          // Russian
		{[]byte{0xff, 0xfe}, false},       // Invalid UTF-8
		{[]byte{0x80, 0x81}, false},       // Invalid continuation bytes
		{[]byte{}, true},                  // Empty is valid
	}

	for _, tt := range tests {
		result := IsValidUTF8(tt.data)
		if result != tt.expected {
			t.Errorf("IsValidUTF8(%v) = %v, want %v", tt.data, result, tt.expected)
		}
	}
}

func TestScanPayload(t *testing.T) {
	cfg := &Config{ScanPayloads: true}
	security := &Security{config: cfg}

	tests := []struct {
		payload  string
		expected string
	}{
		{"SELECT * FROM users", "sqli"},
		{"<script>alert(1)</script>", "xss"},
		{"../../../config.txt", "path_traversal"}, // Only matches path_traversal, not lfi
		{"/etc/passwd", "lfi"},
		{"${jndi:ldap://evil.com}", "log4j"},
		{"__proto__.polluted = true", "prototype_pollution"},
		{"normal text here", ""},
		{"hello world", ""},
	}

	for _, tt := range tests {
		result := security.scanPayload([]byte(tt.payload))
		if result != tt.expected {
			t.Errorf("scanPayload(%s) = %s, want %s", tt.payload, result, tt.expected)
		}
	}
}

func TestValidateFrame(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.MaxFrameSize = 100
	cfg.MaxMessageSize = 1000
	cfg.BlockEmptyMessages = true

	security, err := NewSecurity(cfg)
	if err != nil {
		t.Fatalf("NewSecurity failed: %v", err)
	}
	defer security.Stop()

	conn := &Connection{
		ID:          "test-1",
		RateLimiter: NewRateLimiter(100, 50),
	}

	tests := []struct {
		name    string
		frame   *Frame
		wantErr bool
	}{
		{
			name:    "valid text frame",
			frame:   &Frame{Opcode: OpText, Payload: []byte("Hello")},
			wantErr: false,
		},
		{
			name:    "frame too large",
			frame:   &Frame{Opcode: OpText, Payload: make([]byte, 101)},
			wantErr: true,
		},
		{
			name:    "empty message",
			frame:   &Frame{Opcode: OpText, Payload: []byte{}},
			wantErr: true,
		},
		{
			name:    "threat in payload",
			frame:   &Frame{Opcode: OpText, Payload: []byte("SELECT * FROM users")},
			wantErr: true,
		},
		{
			name:    "control frame always allowed",
			frame:   &Frame{Opcode: OpPing, Payload: []byte{}},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := security.ValidateFrame(conn, tt.frame)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateFrame() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestRegisterConnection(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true

	security, err := NewSecurity(cfg)
	if err != nil {
		t.Fatalf("NewSecurity failed: %v", err)
	}
	defer security.Stop()

	conn := security.RegisterConnection("conn-1", "192.168.1.1", "https://example.com", "/ws")

	if conn == nil {
		t.Fatal("expected connection")
	}

	if conn.ID != "conn-1" {
		t.Errorf("ID = %s, want conn-1", conn.ID)
	}

	if conn.RemoteAddr != "192.168.1.1" {
		t.Errorf("RemoteAddr = %s, want 192.168.1.1", conn.RemoteAddr)
	}

	// Verify it's stored
	retrieved := security.GetConnection("conn-1")
	if retrieved == nil {
		t.Error("connection should be retrievable")
	}

	if len(security.GetAllConnections()) != 1 {
		t.Error("should have 1 connection")
	}

	// Unregister
	security.UnregisterConnection("conn-1")

	if security.GetConnection("conn-1") != nil {
		t.Error("connection should be removed")
	}
}

func TestGetConnectionCountForIP(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true

	security, err := NewSecurity(cfg)
	if err != nil {
		t.Fatalf("NewSecurity failed: %v", err)
	}
	defer security.Stop()

	// Register multiple connections from same IP
	security.RegisterConnection("conn-1", "192.168.1.1", "", "/ws")
	security.RegisterConnection("conn-2", "192.168.1.1", "", "/ws")
	security.RegisterConnection("conn-3", "192.168.1.2", "", "/ws")

	if count := security.getConnectionCountForIP("192.168.1.1"); count != 2 {
		t.Errorf("count for 192.168.1.1 = %d, want 2", count)
	}

	if count := security.getConnectionCountForIP("192.168.1.2"); count != 1 {
		t.Errorf("count for 192.168.1.2 = %d, want 1", count)
	}

	if count := security.getConnectionCountForIP("192.168.1.3"); count != 0 {
		t.Errorf("count for 192.168.1.3 = %d, want 0", count)
	}
}

func TestGetClientIP(t *testing.T) {
	tests := []struct {
		name       string
		xff        string
		xri        string
		remoteAddr string
		expected   string
	}{
		{
			name:       "X-Forwarded-For",
			xff:        "203.0.113.195, 70.41.3.18, 150.172.238.178",
			remoteAddr: "192.168.1.1:1234",
			expected:   "203.0.113.195",
		},
		{
			name:       "X-Real-Ip",
			xri:        "203.0.113.195",
			remoteAddr: "192.168.1.1:1234",
			expected:   "203.0.113.195",
		},
		{
			name:       "RemoteAddr only",
			remoteAddr: "192.168.1.1:1234",
			expected:   "192.168.1.1",
		},
		{
			name:       "RemoteAddr without port",
			remoteAddr: "192.168.1.1",
			expected:   "192.168.1.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &http.Request{
				RemoteAddr: tt.remoteAddr,
				Header:     http.Header{},
			}
			if tt.xff != "" {
				req.Header.Set("X-Forwarded-For", tt.xff)
			}
			if tt.xri != "" {
				req.Header.Set("X-Real-Ip", tt.xri)
			}

			result := getClientIP(req)
			if result != tt.expected {
				t.Errorf("getClientIP() = %s, want %s", result, tt.expected)
			}
		})
	}
}

func TestFrame_IsControl(t *testing.T) {
	tests := []struct {
		opcode   byte
		expected bool
	}{
		{OpContinuation, false},
		{OpText, false},
		{OpBinary, false},
		{OpClose, true},
		{OpPing, true},
		{OpPong, true},
	}

	for _, tt := range tests {
		frame := &Frame{Opcode: tt.opcode}
		if result := frame.IsControl(); result != tt.expected {
			t.Errorf("IsControl(opcode=%d) = %v, want %v", tt.opcode, result, tt.expected)
		}
	}
}

func TestFrame_IsData(t *testing.T) {
	tests := []struct {
		opcode   byte
		expected bool
	}{
		{OpContinuation, true},
		{OpText, true},
		{OpBinary, true},
		{OpClose, false},
		{OpPing, false},
		{OpPong, false},
	}

	for _, tt := range tests {
		frame := &Frame{Opcode: tt.opcode}
		if result := frame.IsData(); result != tt.expected {
			t.Errorf("IsData(opcode=%d) = %v, want %v", tt.opcode, result, tt.expected)
		}
	}
}

func TestCreateCloseFrame(t *testing.T) {
	frame := CreateCloseFrame(1000, "Normal closure")

	if frame.Opcode != OpClose {
		t.Errorf("Opcode = %d, want OpClose", frame.Opcode)
	}

	if !frame.Fin {
		t.Error("Close frame should be final")
	}

	// Payload should contain 2-byte code + reason
	expectedLen := 2 + len("Normal closure")
	if len(frame.Payload) != expectedLen {
		t.Errorf("Payload length = %d, want %d", len(frame.Payload), expectedLen)
	}

	// Check code
	code := binary.BigEndian.Uint16(frame.Payload[:2])
	if code != 1000 {
		t.Errorf("Close code = %d, want 1000", code)
	}
}

func TestCreateTextFrame(t *testing.T) {
	frame := CreateTextFrame("Hello, WebSocket!")

	if frame.Opcode != OpText {
		t.Errorf("Opcode = %d, want OpText", frame.Opcode)
	}

	if !bytes.Equal(frame.Payload, []byte("Hello, WebSocket!")) {
		t.Errorf("Payload = %s", frame.Payload)
	}
}

func TestCreatePongFrame(t *testing.T) {
	pingPayload := []byte("ping data")
	frame := CreatePongFrame(pingPayload)

	if frame.Opcode != OpPong {
		t.Errorf("Opcode = %d, want OpPong", frame.Opcode)
	}

	if !bytes.Equal(frame.Payload, pingPayload) {
		t.Errorf("Payload = %v, want %v", frame.Payload, pingPayload)
	}
}

func TestLayer_NewLayer(t *testing.T) {
	cfg := &Config{Enabled: false}

	layer, err := NewLayer(cfg)
	if err != nil {
		t.Fatalf("NewLayer failed: %v", err)
	}

	if layer.security != nil {
		t.Error("security should be nil when disabled")
	}

	if layer.Name() != "websocket" {
		t.Errorf("name = %s, want websocket", layer.Name())
	}
}

func TestLayer_Process_NotUpgrade(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true

	layer, err := NewLayer(cfg)
	if err != nil {
		t.Fatalf("NewLayer failed: %v", err)
	}
	defer layer.Stop()

	// Regular HTTP request (not WebSocket)
	req := &http.Request{
		Method: "GET",
		URL:    &url.URL{Path: "/api/test"},
		Header: http.Header{},
	}

	ctx := &engine.RequestContext{
		Request: req,
	}

	result := layer.Process(ctx)

	if result.Action != engine.ActionPass {
		t.Errorf("action = %v, want pass", result.Action)
	}
}

func TestLayer_Process_InvalidHandshake(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.AllowedOrigins = []string{"https://example.com"}

	layer, err := NewLayer(cfg)
	if err != nil {
		t.Fatalf("NewLayer failed: %v", err)
	}
	defer layer.Stop()

	// WebSocket upgrade with wrong origin
	req := &http.Request{
		Method: "GET",
		URL:    &url.URL{Path: "/ws"},
		Header: http.Header{
			"Upgrade":               []string{"websocket"},
			"Connection":            []string{"Upgrade"},
			"Sec-WebSocket-Key":     []string{"dGhlIHNhbXBsZSBub25jZQ=="},
			"Origin":                []string{"https://evil.com"},
		},
	}

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

func TestLayer_Process_ConnectionLimit(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.MaxConcurrentPerIP = 1

	layer, err := NewLayer(cfg)
	if err != nil {
		t.Fatalf("NewLayer failed: %v", err)
	}
	defer layer.Stop()

	// Register first connection
	layer.security.RegisterConnection("conn-1", "192.168.1.1", "", "/ws")

	// Try second connection from same IP
	req := &http.Request{
		Method: "GET",
		URL:    &url.URL{Path: "/ws"},
		Header: http.Header{
			"Upgrade":               []string{"websocket"},
			"Connection":            []string{"Upgrade"},
			"Sec-WebSocket-Key":     []string{"dGhlIHNhbXBsZSBub25jZQ=="},
		},
		RemoteAddr: "192.168.1.1:1234",
	}

	ctx := &engine.RequestContext{
		Request: req,
	}

	result := layer.Process(ctx)

	if result.Action != engine.ActionBlock {
		t.Errorf("action = %v, want block", result.Action)
	}
}

func TestCleanupLoop(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.IdleTimeout = 100 * time.Millisecond

	security, err := NewSecurity(cfg)
	if err != nil {
		t.Fatalf("NewSecurity failed: %v", err)
	}
	defer security.Stop()

	// Register a connection
	conn := security.RegisterConnection("conn-1", "192.168.1.1", "", "/ws")
	if conn == nil {
		t.Fatal("expected connection to be registered")
	}

	// Wait for idle timeout to pass
	time.Sleep(150 * time.Millisecond)

	// Trigger cleanup manually (since ticker runs every 30s)
	security.CleanupStaleConnections()

	// Connection should be cleaned up
	if security.GetConnection("conn-1") != nil {
		t.Error("idle connection should be cleaned up")
	}
}
