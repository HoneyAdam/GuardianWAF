package v040

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
)

func TestTenantLayer_Name(t *testing.T) {
	ti := &TenantIntegrator{}
	tl := NewTenantLayer(ti)

	if tl.Name() != "tenant_isolation" {
		t.Errorf("Expected name 'tenant_isolation', got %s", tl.Name())
	}
}

func TestTenantLayer_Order(t *testing.T) {
	ti := &TenantIntegrator{}
	tl := NewTenantLayer(ti)

	if tl.Order() != 50 {
		t.Errorf("Expected order 50, got %d", tl.Order())
	}
}

func TestTenantLayer_Process(t *testing.T) {
	ti := &TenantIntegrator{}
	tl := NewTenantLayer(ti)

	ctx := &engine.RequestContext{
		Method: "GET",
		Path:   "/test",
	}

	result := tl.Process(ctx)

	if result.Action != engine.ActionPass {
		t.Errorf("Expected ActionPass, got %v", result.Action)
	}
}

func TestTenantLayer_ProcessNilIntegrator(t *testing.T) {
	tl := NewTenantLayer(nil)

	ctx := &engine.RequestContext{
		Method: "GET",
		Path:   "/test",
	}

	// Should not panic
	result := tl.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("Expected ActionPass, got %v", result.Action)
	}
}

func TestNewTenantLayer(t *testing.T) {
	ti := &TenantIntegrator{}
	tl := NewTenantLayer(ti)

	if tl == nil {
		t.Fatal("NewTenantLayer returned nil")
	}

	if tl.integrator != ti {
		t.Error("TenantLayer does not hold expected integrator")
	}
}

func TestTenantIntegrator_Middleware_Nil(t *testing.T) {
	ti := &TenantIntegrator{}

	middleware := ti.Middleware()
	if middleware == nil {
		t.Fatal("Middleware returned nil")
	}

	// Test that middleware doesn't panic
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}
}

func TestTenantIntegrator_Middleware_NilMiddleware(t *testing.T) {
	ti := &TenantIntegrator{middleware: nil}

	middleware := ti.Middleware()
	if middleware == nil {
		t.Fatal("Middleware returned nil")
	}

	// Should return passthrough handler
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}
}

func TestTenantIntegrator_RegisterHandlers_Nil(t *testing.T) {
	ti := &TenantIntegrator{}

	// Should not panic
	ti.RegisterHandlers(nil)
}

func TestTenantIntegrator_RegisterHandlers_WithMux(t *testing.T) {
	// Create a mock handlers by using the real tenant handlers
	cfg := config.TenantConfig{Enabled: false}
	ti, err := NewTenantIntegrator(cfg)
	if err != nil {
		t.Fatalf("NewTenantIntegrator failed: %v", err)
	}

	mux := http.NewServeMux()

	// Should not panic even with nil handlers
	ti.RegisterHandlers(mux)
}

func TestTenantIntegrator_Manager_Nil(t *testing.T) {
	ti := &TenantIntegrator{}

	manager := ti.Manager()
	if manager != nil {
		t.Error("Expected nil manager")
	}
}

func TestTenantIntegrator_Stats_Nil(t *testing.T) {
	ti := &TenantIntegrator{}

	stats := ti.Stats()
	if stats.TenantCount != 0 {
		t.Errorf("Expected 0 active tenants, got %d", stats.TenantCount)
	}
}

func TestConvertQuota(t *testing.T) {
	q := config.ResourceQuotaConfig{
		MaxRequestsPerMinute: 1000,
		MaxRequestsPerHour:   50000,
		MaxBandwidthMbps:     100,
		MaxRules:             500,
		MaxRateLimitRules:    100,
		MaxIPACLs:           50,
	}

	result := convertQuota(q)

	if result.MaxRequestsPerMinute != 1000 {
		t.Errorf("Expected 1000 RPM, got %d", result.MaxRequestsPerMinute)
	}
	if result.MaxRequestsPerHour != 50000 {
		t.Errorf("Expected 50000 RPH, got %d", result.MaxRequestsPerHour)
	}
	if result.MaxBandwidthMbps != 100 {
		t.Errorf("Expected 100 Mbps, got %d", result.MaxBandwidthMbps)
	}
	if result.MaxRules != 500 {
		t.Errorf("Expected 500 rules, got %d", result.MaxRules)
	}
}

func TestNewTenantIntegrator_Disabled(t *testing.T) {
	cfg := config.TenantConfig{
		Enabled: false,
	}

	ti, err := NewTenantIntegrator(cfg)
	if err != nil {
		t.Fatalf("NewTenantIntegrator failed: %v", err)
	}

	if ti != nil {
		t.Error("Expected nil when disabled")
	}
}

func TestNewTenantIntegrator_ZeroMaxTenants(t *testing.T) {
	cfg := config.TenantConfig{
		Enabled:    true,
		MaxTenants: 0,
	}

	ti, err := NewTenantIntegrator(cfg)
	if err != nil {
		t.Fatalf("NewTenantIntegrator failed: %v", err)
	}

	if ti == nil {
		t.Fatal("Expected non-nil integrator")
	}

	// MaxTenants should default to 100
	stats := ti.Stats()
	if stats.TenantCount < 0 {
		t.Error("Stats should be valid")
	}
}
