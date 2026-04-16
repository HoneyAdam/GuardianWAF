package engine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/config"
)

// TestAccessLog_TenantID_PresentInLogEntry verifies that when a request carries
// tenant context, the TenantID appears in the access log entry.
//
// Regression test: engine.go used to read ctx.TenantID *after* ReleaseContext()
// had already zeroed it. The fix captured tenantID before the release call.
func TestAccessLog_TenantID_PresentInLogEntry(t *testing.T) {
	e, _, _ := testEngine(t)
	defer e.Close()

	const wantTenantID = "tenant-abc-123"

	// Capture the access log entry produced by the middleware.
	var captured AccessLogEntry
	e.SetAccessLog(func(entry AccessLogEntry) {
		captured = entry
	})

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	handler := e.Middleware(next)
	rec := httptest.NewRecorder()

	// Build a request and attach tenant context.
	r := httptest.NewRequest("GET", "/tenant-log-test", nil)
	r.RemoteAddr = "10.0.0.1:43210"
	r = r.WithContext(WithTenantContext(r.Context(), &TenantContext{
		ID:        wantTenantID,
		WAFConfig: &config.WAFConfig{},
	}))

	handler.ServeHTTP(rec, r)

	// Verify the request passed through successfully.
	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	// Verify TenantID was captured in the access log entry.
	if captured.TenantID != wantTenantID {
		t.Errorf("access log TenantID = %q, want %q", captured.TenantID, wantTenantID)
	}

	// Sanity-check other fields that should also be populated.
	if captured.Path != "/tenant-log-test" {
		t.Errorf("access log Path = %q, want /tenant-log-test", captured.Path)
	}
	if captured.Method != "GET" {
		t.Errorf("access log Method = %q, want GET", captured.Method)
	}
	if captured.Action != "pass" {
		t.Errorf("access log Action = %q, want pass", captured.Action)
	}
	if captured.RequestID == "" {
		t.Error("access log RequestID should not be empty")
	}
}

// TestAccessLog_TenantID_EmptyWhenNoTenant verifies that the TenantID field in
// access log entries is empty for requests without tenant context.
func TestAccessLog_TenantID_EmptyWhenNoTenant(t *testing.T) {
	e, _, _ := testEngine(t)
	defer e.Close()

	var captured AccessLogEntry
	e.SetAccessLog(func(entry AccessLogEntry) {
		captured = entry
	})

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := e.Middleware(next)

	rec := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/no-tenant", nil)
	r.RemoteAddr = "10.0.0.2:43210"

	handler.ServeHTTP(rec, r)

	if captured.TenantID != "" {
		t.Errorf("access log TenantID should be empty for non-tenant request, got %q", captured.TenantID)
	}
}

// TestAccessLog_TenantID_PresentOnBlockedRequest verifies that TenantID appears
// in the access log even when the request is blocked (ActionBlock).
func TestAccessLog_TenantID_PresentOnBlockedRequest(t *testing.T) {
	e, _, _ := testEngine(t)
	defer e.Close()

	const wantTenantID = "tenant-block-789"

	// Add a block layer so the request gets blocked.
	e.AddLayer(OrderedLayer{
		Layer: &blockLayer{name: "ip-acl-blocker"},
		Order: OrderIPACL,
	})

	var captured AccessLogEntry
	e.SetAccessLog(func(entry AccessLogEntry) {
		captured = entry
	})

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	handler := e.Middleware(next)

	rec := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/tenant-blocked", nil)
	r.RemoteAddr = "10.0.0.3:43210"
	r = r.WithContext(WithTenantContext(r.Context(), &TenantContext{
		ID:        wantTenantID,
		WAFConfig: &config.WAFConfig{},
	}))

	handler.ServeHTTP(rec, r)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected status 403, got %d", rec.Code)
	}
	if captured.TenantID != wantTenantID {
		t.Errorf("access log TenantID on blocked request = %q, want %q", captured.TenantID, wantTenantID)
	}
	if captured.Action != "block" {
		t.Errorf("access log Action = %q, want block", captured.Action)
	}
}

// TestAccessLog_TenantID_Concurrent verifies TenantID correctness under concurrent
// requests with different tenant IDs. This exercises the sync.Pool reuse path
// that originally caused the bug.
func TestAccessLog_TenantID_Concurrent(t *testing.T) {
	e, _, _ := testEngine(t)
	defer e.Close()

	const goroutines = 50

	// Collect all access log entries from a single shared callback.
	logEntries := make(chan AccessLogEntry, goroutines)
	e.SetAccessLog(func(entry AccessLogEntry) {
		logEntries <- entry
	})

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := e.Middleware(next)

	// Build all tenant IDs upfront so we can verify them later.
	tenantIDs := make(map[string]bool, goroutines)
	for i := range goroutines {
		tenantIDs["tenant-"+itoa(i)] = true
	}

	for i := range goroutines {
		go func(idx int) {
			tenantID := "tenant-" + itoa(idx)

			rec := httptest.NewRecorder()
			r := httptest.NewRequest("GET", "/concurrent/"+itoa(idx), nil)
			r.RemoteAddr = "127.0.0.1:12345"
			r = r.WithContext(WithTenantContext(r.Context(), &TenantContext{
				ID:        tenantID,
				WAFConfig: &config.WAFConfig{},
			}))

			handler.ServeHTTP(rec, r)
		}(i)
	}

	// Collect and verify all log entries.
	for range goroutines {
		entry := <-logEntries
		if entry.TenantID == "" {
			t.Errorf("access log entry for path %q has empty TenantID", entry.Path)
			continue
		}
		if !tenantIDs[entry.TenantID] {
			t.Errorf("access log TenantID %q does not match any expected tenant", entry.TenantID)
			continue
		}
		// Verify the TenantID matches the path suffix (tenant-N -> /concurrent/N).
		expected := "tenant-" + entry.Path[len("/concurrent/"):]
		if entry.TenantID != expected {
			t.Errorf("access log path %q has TenantID %q, want %q", entry.Path, entry.TenantID, expected)
		}
		delete(tenantIDs, entry.TenantID)
	}

	// All tenant IDs should have been seen.
	if len(tenantIDs) > 0 {
		remaining := make([]string, 0, len(tenantIDs))
		for id := range tenantIDs {
			remaining = append(remaining, id)
		}
		t.Errorf("missing access log entries for tenants: %v", remaining)
	}
}

// TestAccessLog_TenantID_PropagatedViaContext verifies the full path:
// TenantContext set on request context -> Middleware extracts it -> sets
// ctx.TenantID on RequestContext -> captured before ReleaseContext -> appears
// in access log.
func TestAccessLog_TenantID_PropagatedViaContext(t *testing.T) {
	e, _, _ := testEngine(t)
	defer e.Close()

	const wantTenantID = "tenant-ctx-propagation"

	// Add an inspector layer to verify TenantID is set on RequestContext
	// before it enters the pipeline.
	var pipelineSawTenantID string
	e.AddLayer(OrderedLayer{
		Layer: &inspectorLayer{
			name: "tenant-inspector",
			inspect: func(ctx *RequestContext) {
				pipelineSawTenantID = ctx.TenantID
			},
		},
		Order: OrderSanitizer,
	})

	var logTenantID string
	e.SetAccessLog(func(entry AccessLogEntry) {
		logTenantID = entry.TenantID
	})

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := e.Middleware(next)

	rec := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/propagation-test", nil)
	r.RemoteAddr = "10.0.0.5:9999"
	r = r.WithContext(WithTenantContext(r.Context(), &TenantContext{
		ID:        wantTenantID,
		WAFConfig: &config.WAFConfig{},
	}))

	handler.ServeHTTP(rec, r)

	// The pipeline layer should have seen the tenant ID on the RequestContext.
	if pipelineSawTenantID != wantTenantID {
		t.Errorf("pipeline saw TenantID = %q, want %q", pipelineSawTenantID, wantTenantID)
	}

	// The access log should also have the tenant ID (captured before ReleaseContext).
	if logTenantID != wantTenantID {
		t.Errorf("access log TenantID = %q, want %q", logTenantID, wantTenantID)
	}
}

// TestAccessLog_TenantID_WithWAFConfigOverride verifies that when a tenant has
// both an ID and a WAF config override, the TenantID still appears correctly
// in the access log.
func TestAccessLog_TenantID_WithWAFConfigOverride(t *testing.T) {
	e, _, _ := testEngine(t)
	defer e.Close()

	const wantTenantID = "tenant-waf-override"

	tenantWAF := &config.WAFConfig{
		Detection: config.DetectionConfig{
			Enabled: true,
			Threshold: config.ThresholdConfig{
				Block: 40,
				Log:   20,
			},
		},
	}

	var captured AccessLogEntry
	e.SetAccessLog(func(entry AccessLogEntry) {
		captured = entry
	})

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := e.Middleware(next)

	rec := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/waf-override-test", nil)
	r.RemoteAddr = "10.0.0.6:43210"
	r = r.WithContext(WithTenantContext(context.Background(), &TenantContext{
		ID:        wantTenantID,
		WAFConfig: tenantWAF,
	}))

	handler.ServeHTTP(rec, r)

	if captured.TenantID != wantTenantID {
		t.Errorf("access log TenantID = %q, want %q", captured.TenantID, wantTenantID)
	}
}
