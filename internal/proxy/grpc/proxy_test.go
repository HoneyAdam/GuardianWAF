package grpc

import (
	"bytes"
	"encoding/binary"
	"math"
	"net/http/httptest"
	"testing"
)

func TestIsGRPCRequest(t *testing.T) {
	tests := []struct {
		name      string
		contentType string
		expected  bool
	}{
		{
			name:      "gRPC request",
			contentType: "application/grpc",
			expected:  true,
		},
		{
			name:      "gRPC-Web request",
			contentType: "application/grpc-web",
			expected:  true,
		},
		{
			name:      "gRPC with charset",
			contentType: "application/grpc; charset=utf-8",
			expected:  true,
		},
		{
			name:      "regular JSON",
			contentType: "application/json",
			expected:  false,
		},
		{
			name:      "empty content type",
			contentType: "",
			expected:  false,
		},
		{
			name:      "protobuf",
			contentType: "application/x-protobuf",
			expected:  false, // Not a gRPC content type
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/test", nil)
			if tt.contentType != "" {
				req.Header.Set("Content-Type", tt.contentType)
			}

			result := IsGRPCRequest(req)
			if result != tt.expected {
				t.Errorf("IsGRPCRequest() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestIsGRPCWeb(t *testing.T) {
	tests := []struct {
		name      string
		contentType string
		expected  bool
	}{
		{
			name:      "gRPC-Web",
			contentType: "application/grpc-web",
			expected:  true,
		},
		{
			name:      "gRPC-Web text",
			contentType: "application/grpc-web-text",
			expected:  true,
		},
		{
			name:      "gRPC",
			contentType: "application/grpc",
			expected:  false,
		},
		{
			name:      "regular request",
			contentType: "application/json",
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/test", nil)
			if tt.contentType != "" {
				req.Header.Set("Content-Type", tt.contentType)
			}

			result := IsGRPCWeb(req)
			if result != tt.expected {
				t.Errorf("IsGRPCWeb() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestNewProxy(t *testing.T) {
	cfg := &Config{
		Enabled:        true,
		GRPCWebEnabled: true,
		MaxMessageSize: 1024 * 1024,
		ProtoPaths:     []string{}, // Empty for test
	}

	proxy, err := NewProxy(cfg)
	if err != nil {
		t.Fatalf("NewProxy failed: %v", err)
	}

	if proxy == nil {
		t.Fatal("expected proxy, got nil")
	}

	if !proxy.grpcWebEnabled {
		t.Error("grpcWebEnabled should be true")
	}
}

func TestProxy_CanHandle(t *testing.T) {
	cfg := DefaultConfig()
	proxy, err := NewProxy(&cfg)
	if err != nil {
		t.Fatalf("NewProxy failed: %v", err)
	}

	tests := []struct {
		name      string
		contentType string
		expected  bool
	}{
		{
			name:      "gRPC request",
			contentType: "application/grpc",
			expected:  true,
		},
		{
			name:      "gRPC-Web request",
			contentType: "application/grpc-web",
			expected:  true,
		},
		{
			name:      "HTTP JSON",
			contentType: "application/json",
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/test", nil)
			if tt.contentType != "" {
				req.Header.Set("Content-Type", tt.contentType)
			}

			result := proxy.CanHandle(req)
			if result != tt.expected {
				t.Errorf("CanHandle() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestExtractMethodName(t *testing.T) {
	tests := []struct {
		path     string
		expected string
	}{
		{
			path:     "/package.service/Method",
			expected: "Method",
		},
		{
			path:     "/com.example.UserService/GetUser",
			expected: "GetUser",
		},
		{
			path:     "/Method",
			expected: "/Method", // Single segment returns as-is
		},
		{
			path:     "/",
			expected: "/",
		},
		{
			path:     "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			result := extractMethodName(tt.path)
			if result != tt.expected {
				t.Errorf("extractMethodName(%q) = %q, want %q", tt.path, result, tt.expected)
			}
		})
	}
}

func TestParseGRPCFrames(t *testing.T) {
	// Build a simple gRPC frame
	message := []byte("hello world")
	frame := make([]byte, 5+len(message))
	frame[0] = 0 // Not compressed
	binary.BigEndian.PutUint32(frame[1:], uint32(len(message)))
	copy(frame[5:], message)

	messages, err := parseGRPCFrames(frame)
	if err != nil {
		t.Fatalf("parseGRPCFrames failed: %v", err)
	}

	if len(messages) != 1 {
		t.Fatalf("expected 1 message, got %d", len(messages))
	}

	if !bytes.Equal(messages[0], message) {
		t.Errorf("message mismatch: got %q, want %q", messages[0], message)
	}
}

func TestParseGRPCFrames_Multiple(t *testing.T) {
	// Build multiple frames
	msg1 := []byte("first")
	msg2 := []byte("second")

	frame := make([]byte, 10+len(msg1)+len(msg2))
	offset := 0

	// First message
	frame[offset] = 0
	binary.BigEndian.PutUint32(frame[offset+1:], uint32(len(msg1)))
	copy(frame[offset+5:], msg1)
	offset += 5 + len(msg1)

	// Second message
	frame[offset] = 0
	binary.BigEndian.PutUint32(frame[offset+1:], uint32(len(msg2)))
	copy(frame[offset+5:], msg2)

	messages, err := parseGRPCFrames(frame)
	if err != nil {
		t.Fatalf("parseGRPCFrames failed: %v", err)
	}

	if len(messages) != 2 {
		t.Fatalf("expected 2 messages, got %d", len(messages))
	}

	if !bytes.Equal(messages[0], msg1) {
		t.Errorf("first message mismatch: got %q, want %q", messages[0], msg1)
	}
	if !bytes.Equal(messages[1], msg2) {
		t.Errorf("second message mismatch: got %q, want %q", messages[1], msg2)
	}
}

func TestProxy_isMethodAllowed(t *testing.T) {
	tests := []struct {
		name       string
		allowed    []string
		blocked    []string
		method     string
		shouldPass bool
	}{
		{
			name:       "no ACL - allow all",
			allowed:    []string{},
			blocked:    []string{},
			method:     "GetUser",
			shouldPass: true,
		},
		{
			name:       "whitelist - allowed",
			allowed:    []string{"GetUser", "CreateUser"},
			blocked:    []string{},
			method:     "GetUser",
			shouldPass: true,
		},
		{
			name:       "whitelist - not allowed",
			allowed:    []string{"GetUser"},
			blocked:    []string{},
			method:     "DeleteUser",
			shouldPass: false,
		},
		{
			name:       "blocked list",
			allowed:    []string{},
			blocked:    []string{"DeleteUser"},
			method:     "DeleteUser",
			shouldPass: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				Enabled:        true,
				AllowedMethods: tt.allowed,
				BlockedMethods: tt.blocked,
			}

			proxy, err := NewProxy(cfg)
			if err != nil {
				t.Fatalf("NewProxy failed: %v", err)
			}

			result := proxy.isMethodAllowed(tt.method)
			if result != tt.shouldPass {
				t.Errorf("isMethodAllowed(%q) = %v, want %v", tt.method, result, tt.shouldPass)
			}
		})
	}
}

func TestValidator_ValidateMessage(t *testing.T) {
	v, err := NewValidator([]string{})
	if err != nil {
		t.Fatalf("NewValidator failed: %v", err)
	}

	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{
			name:    "empty message",
			data:    []byte{},
			wantErr: true,
		},
		{
			name:    "valid message",
			data:    encodeVarintField(1, 42),
			wantErr: false,
		},
		{
			name:    "large message",
			data:    make([]byte, 5*1024*1024), // 5MB
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.ValidateMessage("TestMethod", tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateMessage() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Enabled {
		t.Error("Enabled should be false by default")
	}
	if !cfg.GRPCWebEnabled {
		t.Error("GRPCWebEnabled should be true by default")
	}
	if cfg.MaxMessageSize != 4*1024*1024 {
		t.Errorf("MaxMessageSize = %d, want %d", cfg.MaxMessageSize, 4*1024*1024)
	}
}

func TestProxy_Stats(t *testing.T) {
	cfg := DefaultConfig()
	proxy, err := NewProxy(&cfg)
	if err != nil {
		t.Fatalf("NewProxy failed: %v", err)
	}

	// Record some stats
	proxy.recordTraffic(100, 50)
	proxy.recordTraffic(200, 100)

	stats := proxy.Stats()

	if stats.RPCCount != 2 {
		t.Errorf("RPCCount = %d, want 2", stats.RPCCount)
	}
	if stats.BytesOut != 300 {
		t.Errorf("BytesOut = %d, want 300", stats.BytesOut)
	}
	if stats.BytesIn != 150 {
		t.Errorf("BytesIn = %d, want 150", stats.BytesIn)
	}
}

// --- Protobuf Wire Format Tests ---

// encodeVarint encodes a uint64 as a protobuf varint.
func encodeVarint(v uint64) []byte {
	var buf [10]byte
	n := 0
	for v >= 0x80 {
		buf[n] = byte(v) | 0x80
		v >>= 7
		n++
	}
	buf[n] = byte(v)
	return buf[:n+1]
}

// encodeField encodes a single protobuf field.
func encodeField(fieldNum int, wireType int, value []byte) []byte {
	tag := uint64(fieldNum<<3 | wireType)
	var buf []byte
	buf = append(buf, encodeVarint(tag)...)
	buf = append(buf, value...)
	return buf
}

// encodeVarintField encodes a varint field.
func encodeVarintField(fieldNum int, value uint64) []byte {
	tag := uint64(fieldNum<<3 | wireVarint)
	var buf []byte
	buf = append(buf, encodeVarint(tag)...)
	buf = append(buf, encodeVarint(value)...)
	return buf
}

// encodeBytesField encodes a length-delimited field.
func encodeBytesField(fieldNum int, value []byte) []byte {
	tag := uint64(fieldNum<<3 | wireBytes)
	var buf []byte
	buf = append(buf, encodeVarint(tag)...)
	buf = append(buf, encodeVarint(uint64(len(value)))...)
	buf = append(buf, value...)
	return buf
}

// encodeFixed32Field encodes a fixed32 field.
func encodeFixed32Field(fieldNum int, value uint32) []byte {
	tag := uint64(fieldNum<<3 | wireFixed32)
	var buf []byte
	buf = append(buf, encodeVarint(tag)...)
	var tmp [4]byte
	binary.LittleEndian.PutUint32(tmp[:], value)
	buf = append(buf, tmp[:]...)
	return buf
}

// encodeFixed64Field encodes a fixed64 field.
func encodeFixed64Field(fieldNum int, value uint64) []byte {
	tag := uint64(fieldNum<<3 | wireFixed64)
	var buf []byte
	buf = append(buf, encodeVarint(tag)...)
	var tmp [8]byte
	binary.LittleEndian.PutUint64(tmp[:], value)
	buf = append(buf, tmp[:]...)
	return buf
}

func TestDecodeVarint(t *testing.T) {
	tests := []struct {
		name  string
		value uint64
	}{
		{"zero", 0},
		{"one", 1},
		{"127", 127},
		{"128", 128},
		{"300", 300},
		{"16383", 16383},
		{"max uint32", 0xFFFFFFFF},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded := encodeVarint(tt.value)
			decoded, n, err := decodeVarint(encoded)
			if err != nil {
				t.Fatalf("decodeVarint failed: %v", err)
			}
			if n != len(encoded) {
				t.Errorf("consumed bytes = %d, want %d", n, len(encoded))
			}
			if decoded != tt.value {
				t.Errorf("decoded = %d, want %d", decoded, tt.value)
			}
		})
	}
}

func TestDecodeVarint_Errors(t *testing.T) {
	// Empty data
	_, _, err := decodeVarint([]byte{})
	if err == nil {
		t.Error("expected error for empty data")
	}

	// All continuation bytes (incomplete varint)
	_, _, err = decodeVarint([]byte{0x80, 0x80, 0x80})
	if err == nil {
		t.Error("expected error for incomplete varint")
	}
}

func TestDecodeWireFormat_VarintField(t *testing.T) {
	data := encodeVarintField(1, 42)
	fields, err := decodeWireFormat(data)
	if err != nil {
		t.Fatalf("decodeWireFormat failed: %v", err)
	}
	if len(fields) != 1 {
		t.Fatalf("expected 1 field, got %d", len(fields))
	}
	if fields[0].FieldNumber != 1 {
		t.Errorf("field number = %d, want 1", fields[0].FieldNumber)
	}
	if fields[0].WireType != wireVarint {
		t.Errorf("wire type = %d, want %d", fields[0].WireType, wireVarint)
	}
	if fields[0].Varint != 42 {
		t.Errorf("varint value = %d, want 42", fields[0].Varint)
	}
}

func TestDecodeWireFormat_BytesField(t *testing.T) {
	payload := []byte("hello world")
	data := encodeBytesField(2, payload)
	fields, err := decodeWireFormat(data)
	if err != nil {
		t.Fatalf("decodeWireFormat failed: %v", err)
	}
	if len(fields) != 1 {
		t.Fatalf("expected 1 field, got %d", len(fields))
	}
	if fields[0].WireType != wireBytes {
		t.Errorf("wire type = %d, want %d", fields[0].WireType, wireBytes)
	}
	if !bytes.Equal(fields[0].Value, payload) {
		t.Errorf("value = %q, want %q", fields[0].Value, payload)
	}
}

func TestDecodeWireFormat_Fixed32(t *testing.T) {
	data := encodeFixed32Field(8, 12345)
	fields, err := decodeWireFormat(data)
	if err != nil {
		t.Fatalf("decodeWireFormat failed: %v", err)
	}
	if len(fields) != 1 {
		t.Fatalf("expected 1 field, got %d", len(fields))
	}
	if fields[0].WireType != wireFixed32 {
		t.Errorf("wire type = %d, want %d", fields[0].WireType, wireFixed32)
	}
	if len(fields[0].Value) != 4 {
		t.Errorf("value length = %d, want 4", len(fields[0].Value))
	}
}

func TestDecodeWireFormat_Fixed64(t *testing.T) {
	data := encodeFixed64Field(9, 12345678901234)
	fields, err := decodeWireFormat(data)
	if err != nil {
		t.Fatalf("decodeWireFormat failed: %v", err)
	}
	if len(fields) != 1 {
		t.Fatalf("expected 1 field, got %d", len(fields))
	}
	if fields[0].WireType != wireFixed64 {
		t.Errorf("wire type = %d, want %d", fields[0].WireType, wireFixed64)
	}
	if len(fields[0].Value) != 8 {
		t.Errorf("value length = %d, want 8", len(fields[0].Value))
	}
}

func TestDecodeWireFormat_MultipleFields(t *testing.T) {
	var data []byte
	data = append(data, encodeVarintField(1, 100)...)
	data = append(data, encodeBytesField(2, []byte("test"))...)
	data = append(data, encodeVarintField(3, 200)...)

	fields, err := decodeWireFormat(data)
	if err != nil {
		t.Fatalf("decodeWireFormat failed: %v", err)
	}
	if len(fields) != 3 {
		t.Fatalf("expected 3 fields, got %d", len(fields))
	}
	if fields[0].FieldNumber != 1 || fields[0].Varint != 100 {
		t.Errorf("field 1: number=%d value=%d", fields[0].FieldNumber, fields[0].Varint)
	}
	if fields[1].FieldNumber != 2 || string(fields[1].Value) != "test" {
		t.Errorf("field 2: number=%d value=%q", fields[1].FieldNumber, fields[1].Value)
	}
	if fields[2].FieldNumber != 3 || fields[2].Varint != 200 {
		t.Errorf("field 3: number=%d value=%d", fields[2].FieldNumber, fields[2].Varint)
	}
}

func TestDecodeWireFormat_FieldNumberZero(t *testing.T) {
	// Field number 0 is invalid
	data := encodeVarintField(0, 1)
	_, err := decodeWireFormat(data)
	if err == nil {
		t.Error("expected error for field number 0")
	}
}

func TestDecodeWireFormat_TruncatedFixed64(t *testing.T) {
	// Fixed64 with insufficient data
	tag := encodeVarint(uint64(1<<3 | wireFixed64))
	data := append(tag, []byte{0x01, 0x02}...) // Only 2 bytes, need 8
	_, err := decodeWireFormat(data)
	if err == nil {
		t.Error("expected error for truncated fixed64")
	}
}

func TestDecodeWireFormat_TruncatedBytes(t *testing.T) {
	// Length-delimited field declares more bytes than available
	tag := encodeVarint(uint64(1<<3 | wireBytes))
	length := encodeVarint(100)
	data := append(tag, length...)
	data = append(data, []byte("short")...) // Only 5 bytes, declared 100
	_, err := decodeWireFormat(data)
	if err == nil {
		t.Error("expected error for truncated bytes field")
	}
}

func TestValidateMessage_WireFormatOnly(t *testing.T) {
	v, err := NewValidator(nil)
	if err != nil {
		t.Fatal(err)
	}

	// Valid protobuf: field 1 = varint 42, field 2 = bytes "hello"
	var data []byte
	data = append(data, encodeVarintField(1, 42)...)
	data = append(data, encodeBytesField(2, []byte("hello"))...)

	err = v.ValidateMessage("UnknownMethod", data)
	if err != nil {
		t.Errorf("valid message should pass: %v", err)
	}
}

func TestValidateMessage_NestedMessage(t *testing.T) {
	v, err := NewValidator(nil)
	if err != nil {
		t.Fatal(err)
	}

	// Nested message: field 1 = embedded message { field 1 = varint 42 }
	inner := encodeVarintField(1, 42)
	outer := encodeBytesField(1, inner)

	err = v.ValidateMessage("Test", outer)
	if err != nil {
		t.Errorf("nested message should pass: %v", err)
	}
}

func TestValidateMessage_InvalidWireFormat(t *testing.T) {
	v, err := NewValidator(nil)
	if err != nil {
		t.Fatal(err)
	}

	// Invalid: bare continuation byte (incomplete varint)
	err = v.ValidateMessage("Test", []byte{0x80, 0x80, 0x80, 0x80})
	if err == nil {
		t.Error("expected error for invalid wire format")
	}
}

func TestValidateMessage_SchemaValidation(t *testing.T) {
	v, err := NewValidator(nil)
	if err != nil {
		t.Fatal(err)
	}

	// Register a schema for "GetUser"
	maxLen := 100
	v.RegisterSchema("GetUser", &MessageType{
		Name: "GetUserRequest",
		Fields: []Field{
			{Name: "user_id", Number: 1, Type: FieldTypeString},
			{Name: "count", Number: 2, Type: FieldTypeUint32},
		},
		Required: []string{"user_id"},
		Constraints: map[string]Constraint{
			"user_id": {MinLen: &[]int{1}[0], MaxLen: &maxLen},
		},
	})

	// Valid message: field 1 = "user123", field 2 = 5
	var data []byte
	data = append(data, encodeBytesField(1, []byte("user123"))...)
	data = append(data, encodeVarintField(2, 5)...)

	err = v.ValidateMessage("GetUser", data)
	if err != nil {
		t.Errorf("valid schema message should pass: %v", err)
	}

	// Missing required field: only field 2 present
	data2 := encodeVarintField(2, 5)
	err = v.ValidateMessage("GetUser", data2)
	if err == nil {
		t.Error("expected error for missing required field")
	}
}

func TestValidateMessage_SchemaMinLen(t *testing.T) {
	v, err := NewValidator(nil)
	if err != nil {
		t.Fatal(err)
	}

	minLen := 5
	v.RegisterSchema("Create", &MessageType{
		Name: "CreateRequest",
		Fields: []Field{
			{Name: "name", Number: 1, Type: FieldTypeString},
		},
		Constraints: map[string]Constraint{
			"name": {MinLen: &minLen},
		},
	})

	// Too short
	data := encodeBytesField(1, []byte("ab"))
	err = v.ValidateMessage("Create", data)
	if err == nil {
		t.Error("expected error for string below min length")
	}

	// Long enough
	data = encodeBytesField(1, []byte("hello world"))
	err = v.ValidateMessage("Create", data)
	if err != nil {
		t.Errorf("valid string should pass: %v", err)
	}
}

func TestValidateMessage_SchemaNumericRange(t *testing.T) {
	v, err := NewValidator(nil)
	if err != nil {
		t.Fatal(err)
	}

	minVal := 1.0
	maxVal := 100.0
	v.RegisterSchema("Update", &MessageType{
		Name: "UpdateRequest",
		Fields: []Field{
			{Name: "priority", Number: 1, Type: FieldTypeUint32},
		},
		Constraints: map[string]Constraint{
			"priority": {MinVal: &minVal, MaxVal: &maxVal},
		},
	})

	// Value in range
	data := encodeVarintField(1, 50)
	err = v.ValidateMessage("Update", data)
	if err != nil {
		t.Errorf("valid value should pass: %v", err)
	}

	// Value too high
	data = encodeVarintField(1, 200)
	err = v.ValidateMessage("Update", data)
	if err == nil {
		t.Error("expected error for value above max")
	}

	// Value zero (below min)
	data = encodeVarintField(1, 0)
	err = v.ValidateMessage("Update", data)
	if err == nil {
		t.Error("expected error for value below min")
	}
}

func TestValidateMessage_SchemaFloatConstraints(t *testing.T) {
	v, err := NewValidator(nil)
	if err != nil {
		t.Fatal(err)
	}

	minVal := 0.0
	maxVal := 1.0
	v.RegisterSchema("Score", &MessageType{
		Name: "ScoreRequest",
		Fields: []Field{
			{Name: "confidence", Number: 1, Type: FieldTypeFloat},
		},
		Constraints: map[string]Constraint{
			"confidence": {MinVal: &minVal, MaxVal: &maxVal},
		},
	})

	// Valid float in range (0.5)
	var tmp [4]byte
	binary.LittleEndian.PutUint32(tmp[:], math.Float32bits(0.5))
	data := encodeField(1, wireFixed32, tmp[:])

	err = v.ValidateMessage("Score", data)
	if err != nil {
		t.Errorf("valid float should pass: %v", err)
	}

	// Float out of range (2.0)
	binary.LittleEndian.PutUint32(tmp[:], math.Float32bits(2.0))
	data = encodeField(1, wireFixed32, tmp[:])

	err = v.ValidateMessage("Score", data)
	if err == nil {
		t.Error("expected error for float above max")
	}
}

func TestValidateMessage_WireTypeMismatch(t *testing.T) {
	v, err := NewValidator(nil)
	if err != nil {
		t.Fatal(err)
	}

	v.RegisterSchema("Test", &MessageType{
		Name: "TestRequest",
		Fields: []Field{
			{Name: "count", Number: 1, Type: FieldTypeUint32}, // expects varint
		},
	})

	// Send bytes field where varint expected
	data := encodeBytesField(1, []byte("not a varint"))
	err = v.ValidateMessage("Test", data)
	if err == nil {
		t.Error("expected error for wire type mismatch")
	}
}

func TestValidateMessage_DeepNesting(t *testing.T) {
	v, err := NewValidator(nil)
	if err != nil {
		t.Fatal(err)
	}

	// Create deeply nested message (deeper than maxNestedDepth=16)
	data := encodeVarintField(1, 42) // innermost
	for i := 0; i < 20; i++ {
		data = encodeBytesField(1, data)
	}

	err = v.ValidateMessage("Deep", data)
	if err == nil {
		t.Error("expected error for excessive nesting depth")
	}
}

func TestValidateMessage_EmbeddedMessageValidation(t *testing.T) {
	v, err := NewValidator(nil)
	if err != nil {
		t.Fatal(err)
	}

	// Register schemas with embedded message
	v.RegisterSchema("inner_msg", &MessageType{
		Name: "Inner",
		Fields: []Field{
			{Name: "value", Number: 1, Type: FieldTypeUint32},
		},
		Required: []string{"value"},
	})
	v.RegisterSchema("Outer", &MessageType{
		Name: "OuterRequest",
		Fields: []Field{
			{Name: "inner", Number: 1, Type: FieldTypeMessage},
		},
	})

	// Valid: outer with inner containing required field
	inner := encodeVarintField(1, 42)
	outer := encodeBytesField(1, inner)

	// This should pass wire format validation (no schema match for "Outer")
	// but will recursively validate the inner message
	err = v.ValidateMessage("Outer", outer)
	if err != nil {
		t.Errorf("valid embedded message should pass: %v", err)
	}
}

func TestValidateMessageDetails_Structural(t *testing.T) {
	v, err := NewValidator(nil)
	if err != nil {
		t.Fatal(err)
	}

	var data []byte
	data = append(data, encodeVarintField(1, 1)...)
	data = append(data, encodeBytesField(2, []byte("test"))...)
	data = append(data, encodeVarintField(3, 99)...)

	result := v.ValidateMessageDetailed("Test", data, 0)
	if len(result.Violations) > 0 {
		t.Errorf("unexpected violations: %v", result.Violations)
	}
	if result.FieldCount != 3 {
		t.Errorf("field count = %d, want 3", result.FieldCount)
	}
}

func TestRegisterAndGetMessageType(t *testing.T) {
	v, err := NewValidator(nil)
	if err != nil {
		t.Fatal(err)
	}

	// Get non-existent
	if mt := v.GetMessageType("Missing"); mt != nil {
		t.Error("expected nil for missing type")
	}

	// Register and retrieve
	mt := &MessageType{
		Name: "TestMsg",
		Fields: []Field{
			{Name: "id", Number: 1, Type: FieldTypeString, Required: true},
		},
		Required: []string{"id"},
	}
	v.RegisterSchema("TestMsg", mt)

	got := v.GetMessageType("TestMsg")
	if got == nil || got.Name != "TestMsg" {
		t.Errorf("GetMessageType = %v, want TestMsg", got)
	}
}
