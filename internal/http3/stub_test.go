//go:build !http3

package http3

import (
	"context"
	"net/http"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg == nil {
		t.Fatal("DefaultConfig returned nil")
	}

	if cfg.Enabled != false {
		t.Errorf("Expected Enabled to be false, got %v", cfg.Enabled)
	}
}

func TestNewServer_Disabled(t *testing.T) {
	cfg := &Config{Enabled: false}
	handler := http.NewServeMux()

	server, err := NewServer(cfg, handler, nil)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	if server == nil {
		t.Fatal("NewServer returned nil server")
	}

	if server.config != cfg {
		t.Error("Server config does not match input config")
	}
}

func TestNewServer_EnabledWithoutBuildTag(t *testing.T) {
	cfg := &Config{Enabled: true}
	handler := http.NewServeMux()

	server, err := NewServer(cfg, handler, nil)
	if err == nil {
		t.Fatal("Expected error when HTTP/3 enabled but built without tag")
	}

	if server != nil {
		t.Error("Expected nil server when HTTP/3 not supported")
	}

	expectedMsg := "HTTP/3 is enabled but GuardianWAF was built without HTTP/3 support. Rebuild with: go build -tags http3"
	if err.Error() != expectedMsg {
		t.Errorf("Unexpected error message: %v", err)
	}
}

func TestServer_Start(t *testing.T) {
	server := &Server{config: &Config{Enabled: false}}

	err := server.Start()
	if err != nil {
		t.Errorf("Start should return nil, got: %v", err)
	}
}

func TestServer_Stop(t *testing.T) {
	server := &Server{config: &Config{Enabled: false}}

	err := server.Stop(context.Background())
	if err != nil {
		t.Errorf("Stop should return nil, got: %v", err)
	}
}

func TestServer_AltSvcHeader(t *testing.T) {
	server := &Server{config: &Config{Enabled: false}}

	header := server.AltSvcHeader()
	if header != "" {
		t.Errorf("AltSvcHeader should return empty string, got: %s", header)
	}
}

func TestServer_IsRunning(t *testing.T) {
	server := &Server{config: &Config{Enabled: false}}

	if server.IsRunning() != false {
		t.Error("IsRunning should return false for stub")
	}
}

func TestServer_GetConfig(t *testing.T) {
	cfg := &Config{Enabled: false, Listen: ":8443"}
	server := &Server{config: cfg}

	result := server.GetConfig()
	if result != cfg {
		t.Error("GetConfig should return the same config")
	}

	if result.Listen != ":8443" {
		t.Errorf("Expected Listen ':8443', got: %s", result.Listen)
	}
}

func TestServer_GetStats(t *testing.T) {
	server := &Server{config: &Config{Enabled: false}}

	stats := server.GetStats()

	// All stats should be zero for stub
	if stats.Connections != 0 {
		t.Errorf("Expected Connections 0, got: %d", stats.Connections)
	}
	if stats.Requests != 0 {
		t.Errorf("Expected Requests 0, got: %d", stats.Requests)
	}
	if stats.Errors != 0 {
		t.Errorf("Expected Errors 0, got: %d", stats.Errors)
	}
	if stats.ZeroRTTUsed != 0 {
		t.Errorf("Expected ZeroRTTUsed 0, got: %d", stats.ZeroRTTUsed)
	}
	if stats.MigrationCount != 0 {
		t.Errorf("Expected MigrationCount 0, got: %d", stats.MigrationCount)
	}
}

func TestEnableAltSvc(t *testing.T) {
	handler := http.NewServeMux()
	next := EnableAltSvc(handler, "h3=\":443\"")

	if next != handler {
		t.Error("EnableAltSvc should return the same handler")
	}
}

func TestIsHTTP3Request(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://example.com/", nil)

	result := IsHTTP3Request(req)
	if result != false {
		t.Error("IsHTTP3Request should return false for stub")
	}
}
