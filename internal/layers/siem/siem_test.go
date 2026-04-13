package siem

import (
	"testing"
	"time"
)

func TestNewFormatter(t *testing.T) {
	f := NewFormatter(FormatCEF, "test-host", "TestWAF", "2.0")

	if f == nil {
		t.Fatal("expected formatter, got nil")
	}

	if f.hostname != "test-host" {
		t.Errorf("hostname = %s, want test-host", f.hostname)
	}

	if f.product != "TestWAF" {
		t.Errorf("product = %s, want TestWAF", f.product)
	}

	if f.version != "2.0" {
		t.Errorf("version = %s, want 2.0", f.version)
	}
}

func TestNewFormatter_Defaults(t *testing.T) {
	f := NewFormatter(FormatJSON, "", "", "")

	if f.hostname != "guardianwaf" {
		t.Errorf("hostname = %s, want guardianwaf", f.hostname)
	}

	if f.product != "GuardianWAF" {
		t.Errorf("product = %s, want GuardianWAF", f.product)
	}

	if f.version != "1.0" {
		t.Errorf("version = %s, want 1.0", f.version)
	}
}

func TestFormatter_Format_JSON(t *testing.T) {
	f := NewFormatter(FormatJSON, "host", "WAF", "1.0")

	event := &Event{
		Timestamp: time.Date(2026, 4, 5, 12, 0, 0, 0, time.UTC),
		EventType: "block",
		Severity:  SeverityHigh,
		SourceIP:  "192.168.1.1",
		Action:    "block",
		Method:    "POST",
		Path:      "/api/data",
		Score:     75,
	}

	result, err := f.Format(event)
	if err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	if result == "" {
		t.Error("expected non-empty result")
	}

	// Check JSON contains expected fields
	if !contains(result, "block") {
		t.Error("expected result to contain 'block'")
	}
	if !contains(result, "192.168.1.1") {
		t.Error("expected result to contain source IP")
	}
}

func TestFormatter_Format_CEF(t *testing.T) {
	f := NewFormatter(FormatCEF, "host", "WAF", "1.0")

	event := &Event{
		Timestamp: time.Date(2026, 4, 5, 12, 0, 0, 0, time.UTC),
		EventType: "block",
		Severity:  SeverityHigh,
		SourceIP:  "192.168.1.1",
		Action:    "block",
		RuleID:    "SQLI-001",
		Reason:    "SQL Injection detected",
		Score:     75,
	}

	result, err := f.Format(event)
	if err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	if result == "" {
		t.Error("expected non-empty result")
	}

	// Check CEF prefix
	if !contains(result, "CEF:0") {
		t.Error("expected CEF prefix")
	}
	if !contains(result, "GuardianWAF") {
		t.Error("expected device vendor")
	}
}

func TestFormatter_Format_LEEF(t *testing.T) {
	f := NewFormatter(FormatLEEF, "host", "WAF", "1.0")

	event := &Event{
		Timestamp: time.Date(2026, 4, 5, 12, 0, 0, 0, time.UTC),
		EventType: "block",
		Severity:  SeverityHigh,
		SourceIP:  "192.168.1.1",
		Action:    "block",
	}

	result, err := f.Format(event)
	if err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	// Check LEEF prefix
	if !contains(result, "LEEF") {
		t.Error("expected LEEF prefix")
	}
}

func TestFormatter_Format_Syslog(t *testing.T) {
	f := NewFormatter(FormatSyslog, "host", "WAF", "1.0")

	event := &Event{
		Timestamp: time.Date(2026, 4, 5, 12, 0, 0, 0, time.UTC),
		EventType: "block",
		Severity:  SeverityHigh,
		SourceIP:  "192.168.1.1",
		Action:    "block",
	}

	result, err := f.Format(event)
	if err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	// Check syslog format
	if !contains(result, "<132>") && !contains(result, "<133>") {
		t.Error("expected syslog priority")
	}
}

func TestFormatter_Format_Splunk(t *testing.T) {
	f := NewFormatter(FormatSplunk, "host", "WAF", "1.0")

	event := &Event{
		Timestamp: time.Date(2026, 4, 5, 12, 0, 0, 0, time.UTC),
		EventType: "block",
		Severity:  SeverityHigh,
		SourceIP:  "192.168.1.1",
		Action:    "block",
	}

	result, err := f.Format(event)
	if err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	// Check Splunk format
	if !contains(result, "time") {
		t.Error("expected time field")
	}
	if !contains(result, "sourcetype") {
		t.Error("expected sourcetype field")
	}
}

func TestFormatter_Format_Elastic(t *testing.T) {
	f := NewFormatter(FormatElastic, "host", "WAF", "1.0")

	event := &Event{
		Timestamp: time.Date(2026, 4, 5, 12, 0, 0, 0, time.UTC),
		EventType: "block",
		Severity:  SeverityHigh,
		SourceIP:  "192.168.1.1",
		Action:    "block",
		RequestID: "req-123",
	}

	result, err := f.Format(event)
	if err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	// Check Elasticsearch format (should have two lines)
	if !contains(result, "index") {
		t.Error("expected index metadata")
	}
	if !contains(result, "event_type") {
		t.Error("expected event data")
	}
}

func TestFormatCEFTimestamp(t *testing.T) {
	ts := time.Date(2026, 4, 5, 12, 30, 45, 0, time.UTC)
	result := formatCEFTimestamp(ts)

	expected := "Apr 05 2026 12:30:45"
	if result != expected {
		t.Errorf("formatCEFTimestamp = %s, want %s", result, expected)
	}
}

func TestFormatLEEFTimestamp(t *testing.T) {
	ts := time.Date(2026, 4, 5, 12, 30, 45, 0, time.UTC)
	result := formatLEEFTimestamp(ts)

	expected := "2026-04-05 12:30:45"
	if result != expected {
		t.Errorf("formatLEEFTimestamp = %s, want %s", result, expected)
	}
}

func TestEscapeCEF(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"hello=world", "hello\\=world"},
		{"a|b", "a\\|b"},
		{"a\\b", "a\\\\b"},
		{"normal", "normal"},
	}

	for _, tt := range tests {
		result := escapeCEF(tt.input)
		if result != tt.expected {
			t.Errorf("escapeCEF(%s) = %s, want %s", tt.input, result, tt.expected)
		}
	}
}

func TestEscapeLEEF(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"hello=world", "hello\\=world"},
		{"a\\t", "a\\\\t"},
		{"a\\b", "a\\\\b"},
		{"normal", "normal"},
	}

	for _, tt := range tests {
		result := escapeLEEF(tt.input)
		if result != tt.expected {
			t.Errorf("escapeLEEF(%s) = %s, want %s", tt.input, result, tt.expected)
		}
	}
}

func TestNewExporter(t *testing.T) {
	cfg := &Config{
		Enabled:       true,
		Endpoint:      "https://1.2.3.4:8088",
		Format:        FormatJSON,
		BatchSize:     50,
		FlushInterval: 10 * time.Second,
		Timeout:       30 * time.Second,
	}

	exporter := NewExporter(cfg)

	if exporter == nil {
		t.Fatal("expected exporter, got nil")
	}

	if exporter.config.BatchSize != 50 {
		t.Errorf("BatchSize = %d, want 50", exporter.config.BatchSize)
	}
}

func TestNewExporter_RejectsHTTP(t *testing.T) {
	cfg := &Config{
		Enabled:  true,
		Endpoint: "http://localhost:8088",
		Format:   FormatJSON,
	}
	exporter := NewExporter(cfg)
	if exporter != nil {
		t.Error("expected nil exporter for HTTP endpoint (SSRF protection)")
	}
}

func TestNewExporter_Defaults(t *testing.T) {
	exporter := NewExporter(nil)

	if exporter.config.BatchSize != 100 {
		t.Errorf("BatchSize = %d, want 100", exporter.config.BatchSize)
	}

	if exporter.config.FlushInterval != 5*time.Second {
		t.Errorf("FlushInterval = %v, want 5s", exporter.config.FlushInterval)
	}
}

func TestExporter_Name(t *testing.T) {
	exporter := NewExporter(&Config{Format: FormatSplunk})
	name := exporter.Name()

	if name != "siem-splunk" {
		t.Errorf("Name() = %s, want siem-splunk", name)
	}
}

func TestExporter_IsEnabled(t *testing.T) {
	exporter := NewExporter(&Config{Enabled: true})
	if !exporter.IsEnabled() {
		t.Error("expected exporter to be enabled")
	}

	exporter2 := NewExporter(&Config{Enabled: false})
	if exporter2.IsEnabled() {
		t.Error("expected exporter to be disabled")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && containsAt(s, substr))
}

func containsAt(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
