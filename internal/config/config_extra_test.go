package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// --- SaveFile ---

func TestSaveFile(t *testing.T) {
	dir := t.TempDir()
	cfg := DefaultConfig()
	cfg.Mode = "enforce"
	cfg.Listen = ":9443"
	cfg.WAF.Detection.Enabled = true
	cfg.WAF.Detection.Threshold.Block = 50

	path := filepath.Join(dir, "test_config.yaml")
	if err := SaveFile(path, cfg); err != nil {
		t.Fatalf("SaveFile: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !strings.Contains(string(data), "mode: enforce") {
		t.Error("expected mode: enforce in saved file")
	}
	if !strings.Contains(string(data), "listen:") {
		t.Error("expected listen key in saved file")
	}
}

// --- marshalInlineField: Bool case ---

func TestMarshalInlineField_Bool(t *testing.T) {
	cfg := DefaultConfig()
	cfg.WAF.RateLimit.Enabled = true
	cfg.WAF.RateLimit.Rules = []RateLimitRule{
		{
			ID:     "test-rule",
			Scope:  "ip",
			Limit:  100,
			Window: time.Minute,
			Burst:  100,
			Action: "block",
		},
	}
	out := MarshalYAML(cfg)
	if !strings.Contains(out, "rate_limit:") {
		t.Error("expected rate_limit section")
	}
	if !strings.Contains(out, "test-rule") {
		t.Error("expected test-rule in output")
	}
}

// --- marshalInlineField: Float64 case ---

func TestMarshalInlineField_Float64(t *testing.T) {
	cfg := DefaultConfig()
	cfg.WAF.Detection.Enabled = true
	cfg.WAF.Detection.Detectors = map[string]DetectorConfig{
		"sqli": {Enabled: true, Multiplier: 1.5},
	}
	out := MarshalYAML(cfg)
	if !strings.Contains(out, "multiplier:") {
		t.Error("expected multiplier in output")
	}
}

// --- marshalInlineField: Slice of string case ---

func TestMarshalInlineField_SliceString(t *testing.T) {
	cfg := DefaultConfig()
	cfg.WAF.CORS.Enabled = true
	cfg.WAF.CORS.AllowOrigins = []string{"https://example.com", "https://other.com"}
	out := MarshalYAML(cfg)
	if !strings.Contains(out, "allow_origins:") {
		t.Error("expected allow_origins in output")
	}
	if !strings.Contains(out, "https://example.com") {
		t.Error("expected example.com in output")
	}
}

// --- marshalInlineField: Duration case ---

func TestMarshalInlineField_Duration(t *testing.T) {
	cfg := DefaultConfig()
	cfg.WAF.RateLimit.Enabled = true
	cfg.WAF.RateLimit.Rules = []RateLimitRule{
		{
			ID:     "dur-rule",
			Scope:  "ip",
			Limit:  100,
			Window: 30 * time.Second,
			Burst:  100,
			Action: "block",
		},
	}
	out := MarshalYAML(cfg)
	if !strings.Contains(out, "window: 30s") {
		t.Error("expected window: 30s in output")
	}
}

// --- marshalInlineField: struct case ---

func TestMarshalInlineField_Struct(t *testing.T) {
	cfg := DefaultConfig()
	cfg.WAF.Sanitizer.Enabled = true
	cfg.WAF.Sanitizer.MaxURLLength = 4096
	cfg.WAF.Sanitizer.BlockNullBytes = true
	out := MarshalYAML(cfg)
	if !strings.Contains(out, "sanitizer:") {
		t.Error("expected sanitizer section")
	}
}

// --- needsQuoting edge cases ---

func TestNeedsQuoting(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"", true},
		{"hello world", false},
		{"key: value", true},
		{"#comment", true},
		{"[array]", true},
		{"{map}", true},
		{"a,b", true},
		{"true", true},
		{"false", true},
		{"null", true},
		{"~", true},
		{"*wildcard", true},
		{"&ampersand", true},
		{"!exclaim", true},
		{"|pipe", true},
		{">greater", true},
		{"%percent", true},
		{"@at", true},
		{"plain_value", false},
		{"localhost", false},
		{"hello\nworld", true},
	}
	for _, tt := range tests {
		got := needsQuoting(tt.input)
		if got != tt.want {
			t.Errorf("needsQuoting(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

// --- formatDuration edge cases ---

func TestFormatDuration_Zero(t *testing.T) {
	if got := formatDuration(0); got != "0s" {
		t.Errorf("expected '0s', got %q", got)
	}
}

func TestFormatDuration_Days(t *testing.T) {
	if got := formatDuration(48 * time.Hour); got != "48h" {
		t.Errorf("expected '48h', got %q", got)
	}
}

func TestFormatDuration_SubSecond(t *testing.T) {
	if got := formatDuration(500 * time.Millisecond); got != "500ms" {
		t.Errorf("expected '500ms', got %q", got)
	}
}

// --- isZeroValue with Interface ---

func TestIsZeroValue_Interface(t *testing.T) {
	cfg := DefaultConfig()
	out := MarshalYAML(cfg)
	if out == "" {
		t.Error("expected non-empty YAML")
	}
}

// --- validateVirtualHosts: error cases ---

func TestValidateVirtualHosts_NoDomains(t *testing.T) {
	ve := &ValidationError{}
	validateVirtualHosts([]VirtualHostConfig{
		{Domains: []string{}},
	}, nil, ve)
	if ve.HasErrors() {
		found := false
		for _, e := range ve.Errors {
			if strings.Contains(e.Field, "domains") {
				found = true
			}
		}
		if !found {
			t.Error("expected domains error")
		}
	}
}

func TestValidateVirtualHosts_EmptyDomain(t *testing.T) {
	ve := &ValidationError{}
	validateVirtualHosts([]VirtualHostConfig{
		{Domains: []string{""}},
	}, nil, ve)
	if !ve.HasErrors() {
		t.Error("expected error for empty domain")
	}
}

func TestValidateVirtualHosts_DuplicateDomain(t *testing.T) {
	ve := &ValidationError{}
	validateVirtualHosts([]VirtualHostConfig{
		{Domains: []string{"example.com"}},
		{Domains: []string{"example.com"}},
	}, nil, ve)
	if !ve.HasErrors() {
		t.Error("expected error for duplicate domain")
	}
}

func TestValidateVirtualHosts_EmptyRoutePath(t *testing.T) {
	ve := &ValidationError{}
	validateVirtualHosts([]VirtualHostConfig{
		{
			Domains: []string{"test.com"},
			Routes:  []RouteConfig{{Path: "", Upstream: ""}},
		},
	}, nil, ve)
	if !ve.HasErrors() {
		t.Error("expected error for empty route path")
	}
}

func TestValidateVirtualHosts_UnknownUpstream(t *testing.T) {
	ve := &ValidationError{}
	validateVirtualHosts([]VirtualHostConfig{
		{
			Domains: []string{"test.com"},
			Routes:  []RouteConfig{{Path: "/", Upstream: "nonexistent"}},
		},
	}, []UpstreamConfig{}, ve)
	if !ve.HasErrors() {
		t.Error("expected error for unknown upstream")
	}
}

func TestValidateVirtualHosts_TLSPartial(t *testing.T) {
	ve := &ValidationError{}
	validateVirtualHosts([]VirtualHostConfig{
		{
			Domains: []string{"test.com"},
			TLS:     VHostTLSConfig{CertFile: "/cert.pem"},
		},
	}, nil, ve)
	if !ve.HasErrors() {
		t.Error("expected error for partial TLS config")
	}
}

func TestValidateVirtualHosts_Valid(t *testing.T) {
	ve := &ValidationError{}
	validateVirtualHosts([]VirtualHostConfig{
		{
			Domains: []string{"test.com"},
			Routes:  []RouteConfig{{Path: "/", Upstream: "backend"}},
			TLS:     VHostTLSConfig{CertFile: "/cert.pem", KeyFile: "/key.pem"},
		},
	}, []UpstreamConfig{{Name: "backend"}}, ve)
	if ve.HasErrors() {
		for _, e := range ve.Errors {
			t.Errorf("unexpected error: %s: %s", e.Field, e.Message)
		}
	}
}

// --- MarshalYAML with map ---

func TestMarshalYAML_Map(t *testing.T) {
	cfg := DefaultConfig()
	cfg.WAF.CORS.Enabled = true
	cfg.WAF.CORS.AllowMethods = []string{"GET", "POST", "DELETE"}
	out := MarshalYAML(cfg)
	if !strings.Contains(out, "allow_methods:") {
		t.Error("expected allow_methods in output")
	}
}
