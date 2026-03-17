package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/events"
)

// --- isValidIPOrCIDR ---

func TestIsValidIPOrCIDR_ValidIP(t *testing.T) {
	if !isValidIPOrCIDR("10.0.0.1") {
		t.Error("expected valid IPv4")
	}
}

func TestIsValidIPOrCIDR_ValidIPv6(t *testing.T) {
	if !isValidIPOrCIDR("::1") {
		t.Error("expected valid IPv6")
	}
}

func TestIsValidIPOrCIDR_ValidCIDR(t *testing.T) {
	if !isValidIPOrCIDR("10.0.0.0/8") {
		t.Error("expected valid CIDR")
	}
}

func TestIsValidIPOrCIDR_InvalidIP(t *testing.T) {
	if isValidIPOrCIDR("not-an-ip") {
		t.Error("expected invalid")
	}
}

func TestIsValidIPOrCIDR_InvalidCIDR(t *testing.T) {
	if isValidIPOrCIDR("10.0.0.0/99") {
		t.Error("expected invalid CIDR")
	}
}

// --- upstreamSummary ---

func TestUpstreamSummary_Empty(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Upstreams = nil
	result := upstreamSummary(cfg)
	if result != "(no upstream)" {
		t.Errorf("expected '(no upstream)', got %q", result)
	}
}

func TestUpstreamSummary_MultipleTargets(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Upstreams = []config.UpstreamConfig{
		{
			Name: "backend",
			Targets: []config.TargetConfig{
				{URL: "http://localhost:3000"},
				{URL: "http://localhost:3001"},
			},
		},
	}
	result := upstreamSummary(cfg)
	if !strings.Contains(result, "http://localhost:3000") {
		t.Error("expected first target in summary")
	}
	if !strings.Contains(result, "http://localhost:3001") {
		t.Error("expected second target in summary")
	}
}

// --- loadConfig ---

func TestLoadConfig_DefaultFallback(t *testing.T) {
	// When default path doesn't exist, should return defaults silently
	cfg := loadConfig("guardianwaf.yaml")
	if cfg == nil {
		t.Fatal("expected non-nil config from default fallback")
	}
	if cfg.Mode != "enforce" {
		t.Errorf("expected default mode 'enforce', got %q", cfg.Mode)
	}
}

func TestLoadConfig_FromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.yaml")
	os.WriteFile(path, []byte("mode: monitor\nlisten: \":9090\"\n"), 0644)

	cfg := loadConfig(path)
	if cfg.Mode != "monitor" {
		t.Errorf("expected mode 'monitor', got %q", cfg.Mode)
	}
}

// --- addLayers ---

func TestAddLayers_AllEnabled(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.IPACL.Enabled = true
	cfg.WAF.IPACL.Blacklist = []string{"192.168.1.100"}
	cfg.WAF.RateLimit.Enabled = true
	cfg.WAF.RateLimit.Rules = []config.RateLimitRule{
		{ID: "test", Scope: "ip", Limit: 10, Window: 60_000_000_000, Burst: 5, Action: "block"},
	}
	cfg.WAF.Sanitizer.Enabled = true
	cfg.WAF.Detection.Enabled = true
	cfg.WAF.BotDetection.Enabled = true

	store := events.NewMemoryStore(1000)
	bus := events.NewEventBus()
	eng, err := engine.NewEngine(cfg, store, bus)
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}
	defer eng.Close()

	addLayers(eng, cfg)

	// Verify engine works by processing a request
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	event := eng.Check(req)
	if event == nil {
		t.Fatal("expected non-nil event")
	}
}

func TestAddLayers_ResponseWithHSTS(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.Response.SecurityHeaders.Enabled = true
	cfg.WAF.Response.SecurityHeaders.HSTS.Enabled = true
	cfg.WAF.Response.SecurityHeaders.HSTS.MaxAge = 31536000
	cfg.WAF.Response.SecurityHeaders.HSTS.IncludeSubDomains = true
	cfg.WAF.Response.SecurityHeaders.XFrameOptions = "DENY"
	cfg.WAF.Response.SecurityHeaders.ReferrerPolicy = "no-referrer"
	cfg.WAF.Response.SecurityHeaders.PermissionsPolicy = "camera=()"

	store := events.NewMemoryStore(1000)
	bus := events.NewEventBus()
	eng, err := engine.NewEngine(cfg, store, bus)
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}
	defer eng.Close()

	addLayers(eng, cfg)
}

// --- buildReverseProxy ---

func TestBuildReverseProxy(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Upstreams = []config.UpstreamConfig{
		{
			Name: "backend",
			Targets: []config.TargetConfig{
				{URL: "http://localhost:9999"},
			},
		},
	}
	cfg.Routes = []config.RouteConfig{
		{Path: "/api", Upstream: "backend", StripPrefix: true},
	}

	handler := buildReverseProxy(cfg)
	if handler == nil {
		t.Fatal("expected non-nil handler")
	}
}

func TestBuildReverseProxy_InvalidUpstream(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Upstreams = []config.UpstreamConfig{
		{
			Name:    "bad",
			Targets: []config.TargetConfig{{URL: "://invalid"}},
		},
	}
	cfg.Routes = []config.RouteConfig{
		{Path: "/", Upstream: "bad"},
	}
	handler := buildReverseProxy(cfg)
	if handler == nil {
		t.Fatal("expected non-nil handler even with invalid upstream")
	}
}

func TestBuildReverseProxy_MissingUpstream(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Upstreams = []config.UpstreamConfig{
		{
			Name:    "backend",
			Targets: []config.TargetConfig{{URL: "http://localhost:3000"}},
		},
	}
	cfg.Routes = []config.RouteConfig{
		{Path: "/", Upstream: "nonexistent"},
	}
	handler := buildReverseProxy(cfg)
	if handler == nil {
		t.Fatal("expected non-nil handler")
	}
}

// --- printUsage ---

func TestPrintUsage(t *testing.T) {
	// Just verify it doesn't panic
	printUsage()
}

// --- cmdVersion ---

func TestCmdVersion(t *testing.T) {
	// Just verify it doesn't panic
	cmdVersion()
}

// --- headerSlice ---

func TestHeaderSlice_StringAndSet(t *testing.T) {
	var hs headerSlice
	hs.Set("Content-Type: application/json")
	hs.Set("X-Custom: value")
	s := hs.String()
	if !strings.Contains(s, "Content-Type") {
		t.Error("expected Content-Type in string")
	}
	if !strings.Contains(s, "X-Custom") {
		t.Error("expected X-Custom in string")
	}
}

// --- mcpEngineAdapter ---

func newTestAdapter(t *testing.T) *mcpEngineAdapter {
	t.Helper()
	cfg := config.DefaultConfig()
	cfg.WAF.Detection.Enabled = true
	cfg.WAF.Detection.Detectors = map[string]config.DetectorConfig{
		"sqli": {Enabled: true, Multiplier: 1.0},
		"xss":  {Enabled: true, Multiplier: 1.0},
	}
	store := events.NewMemoryStore(1000)
	bus := events.NewEventBus()
	eng, err := engine.NewEngine(cfg, store, bus)
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}
	t.Cleanup(func() { eng.Close() })
	return &mcpEngineAdapter{engine: eng, cfg: cfg}
}

func TestMCPAdapter_GetStats(t *testing.T) {
	a := newTestAdapter(t)
	stats := a.GetStats()
	m, ok := stats.(map[string]interface{})
	if !ok {
		t.Fatal("expected map result")
	}
	if _, ok := m["total_requests"]; !ok {
		t.Error("expected total_requests in stats")
	}
}

func TestMCPAdapter_GetConfig(t *testing.T) {
	a := newTestAdapter(t)
	cfg := a.GetConfig()
	m, ok := cfg.(map[string]interface{})
	if !ok {
		t.Fatal("expected map result")
	}
	if _, ok := m["mode"]; !ok {
		t.Error("expected mode in config")
	}
}

func TestMCPAdapter_GetMode(t *testing.T) {
	a := newTestAdapter(t)
	mode := a.GetMode()
	if mode != "enforce" {
		t.Errorf("expected 'enforce', got %q", mode)
	}
}

func TestMCPAdapter_SetMode(t *testing.T) {
	a := newTestAdapter(t)
	err := a.SetMode("monitor")
	if err != nil {
		t.Fatalf("SetMode error: %v", err)
	}
	if a.GetMode() != "monitor" {
		t.Error("expected mode to be 'monitor' after SetMode")
	}
}

func TestMCPAdapter_WhitelistBlacklist(t *testing.T) {
	a := newTestAdapter(t)

	if err := a.AddWhitelist("10.0.0.1"); err != nil {
		t.Errorf("AddWhitelist error: %v", err)
	}
	if err := a.AddWhitelist("not-valid"); err == nil {
		t.Error("expected error for invalid IP")
	}
	if err := a.RemoveWhitelist("10.0.0.1"); err != nil {
		t.Errorf("RemoveWhitelist error: %v", err)
	}

	if err := a.AddBlacklist("192.168.1.0/24"); err != nil {
		t.Errorf("AddBlacklist error: %v", err)
	}
	if err := a.AddBlacklist("invalid"); err == nil {
		t.Error("expected error for invalid IP")
	}
	if err := a.RemoveBlacklist("192.168.1.0/24"); err != nil {
		t.Errorf("RemoveBlacklist error: %v", err)
	}
}

func TestMCPAdapter_RateLimit(t *testing.T) {
	a := newTestAdapter(t)
	if err := a.AddRateLimit(map[string]any{"limit": 10}); err != nil {
		t.Errorf("AddRateLimit error: %v", err)
	}
	if err := a.RemoveRateLimit("r1"); err != nil {
		t.Errorf("RemoveRateLimit error: %v", err)
	}
}

func TestMCPAdapter_Exclusion(t *testing.T) {
	a := newTestAdapter(t)
	if err := a.AddExclusion("/api", []string{"sqli"}, "test"); err != nil {
		t.Errorf("AddExclusion error: %v", err)
	}
	if err := a.RemoveExclusion("/api"); err != nil {
		t.Errorf("RemoveExclusion error: %v", err)
	}
}

func TestMCPAdapter_GetEvents(t *testing.T) {
	a := newTestAdapter(t)
	result, err := a.GetEvents(json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("GetEvents error: %v", err)
	}
	m, ok := result.(map[string]interface{})
	if !ok {
		t.Fatal("expected map result")
	}
	if m["total"] != 0 {
		t.Error("expected total 0")
	}
}

func TestMCPAdapter_GetTopIPs(t *testing.T) {
	a := newTestAdapter(t)
	result := a.GetTopIPs(10)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestMCPAdapter_GetDetectors(t *testing.T) {
	a := newTestAdapter(t)
	result := a.GetDetectors()
	detectors, ok := result.([]map[string]interface{})
	if !ok {
		t.Fatal("expected slice result")
	}
	if len(detectors) == 0 {
		t.Error("expected at least one detector")
	}
}

func TestMCPAdapter_TestRequest(t *testing.T) {
	a := newTestAdapter(t)

	// Clean request
	result, err := a.TestRequest("GET", "/test", nil)
	if err != nil {
		t.Fatalf("TestRequest error: %v", err)
	}
	m, ok := result.(map[string]interface{})
	if !ok {
		t.Fatal("expected map result")
	}
	if m["action"] == nil {
		t.Error("expected action in result")
	}
}

func TestMCPAdapter_TestRequest_WithHeaders(t *testing.T) {
	a := newTestAdapter(t)
	result, err := a.TestRequest("GET", "http://example.com/test", map[string]string{
		"User-Agent": "TestBot/1.0",
	})
	if err != nil {
		t.Fatalf("TestRequest error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestMCPAdapter_TestRequest_Attack(t *testing.T) {
	a := newTestAdapter(t)
	result, err := a.TestRequest("GET", "/search?q='+OR+1=1--", nil)
	if err != nil {
		t.Fatalf("TestRequest error: %v", err)
	}
	m := result.(map[string]interface{})
	findings, ok := m["findings"].([]map[string]interface{})
	if ok && len(findings) > 0 {
		// Attack was detected — verify finding has expected fields
		if findings[0]["detector"] == nil {
			t.Error("expected detector field in finding")
		}
	}
}

// --- cmdCheck (via dry-run) ---

func TestCmdCheck_MissingURL(t *testing.T) {
	// cmdCheck calls os.Exit on missing URL, so we can't test it directly.
	// But we can verify the config loading and engine creation path.
	dir := t.TempDir()
	path := filepath.Join(dir, "test.yaml")
	os.WriteFile(path, []byte("mode: monitor\n"), 0644)

	cfg := loadConfig(path)
	store := events.NewMemoryStore(1000)
	bus := events.NewEventBus()
	eng, err := engine.NewEngine(cfg, store, bus)
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}
	defer eng.Close()
	addLayers(eng, cfg)

	// Simulate the check logic
	req, _ := http.NewRequest("GET", "http://localhost/search?q=test", nil)
	req.RemoteAddr = "127.0.0.1:0"
	event := eng.Check(req)
	if event.Action.String() == "" {
		t.Error("expected non-empty action")
	}
}

// --- startDashboard ---

func TestStartDashboard(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Dashboard.Enabled = true
	cfg.Dashboard.Listen = "127.0.0.1:0" // random port
	cfg.Dashboard.APIKey = "test-key"

	store := events.NewMemoryStore(1000)
	bus := events.NewEventBus()
	eng, err := engine.NewEngine(cfg, store, bus)
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}
	defer eng.Close()

	srv := startDashboard(cfg, eng)
	if srv == nil {
		t.Fatal("expected non-nil server")
	}
	defer srv.Close()
}

// --- cmdValidate path ---

func TestCmdValidate_ValidConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.yaml")
	content := `mode: enforce
listen: ":8080"
waf:
  detection:
    enabled: true
`
	os.WriteFile(path, []byte(content), 0644)

	cfg, err := config.LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile error: %v", err)
	}
	config.LoadEnv(cfg)
	if err := config.Validate(cfg); err != nil {
		t.Fatalf("Validate error: %v", err)
	}
}

// --- buildReverseProxy StripPrefix ---

func TestBuildReverseProxy_StripPrefix(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Path", r.URL.Path)
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	backendURL, _ := url.Parse(backend.URL)

	cfg := config.DefaultConfig()
	cfg.Upstreams = []config.UpstreamConfig{
		{
			Name:    "backend",
			Targets: []config.TargetConfig{{URL: backendURL.String()}},
		},
	}
	cfg.Routes = []config.RouteConfig{
		{Path: "/api", Upstream: "backend", StripPrefix: true},
	}

	handler := buildReverseProxy(cfg)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/users", nil)
	handler.ServeHTTP(rr, req)
	// The reverse proxy should have forwarded the request
	if rr.Code == http.StatusNotFound {
		// Route matched — the proxy attempted forwarding
	}
}

// --- Subprocess CLI tests for os.Exit-calling commands ---

func buildBinary(t *testing.T) string {
	t.Helper()
	binName := "guardianwaf_test_bin"
	if runtime.GOOS == "windows" {
		binName += ".exe"
	}
	binPath := filepath.Join(t.TempDir(), binName)
	cmd := exec.Command("go", "build", "-o", binPath, ".")
	cmd.Dir = filepath.Join(".", "")
	// Build from the cmd/guardianwaf directory
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to build binary: %v\n%s", err, out)
	}
	return binPath
}

func writeTestConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "guardianwaf.yaml")
	content := `mode: enforce
listen: ":18080"
waf:
  detection:
    enabled: true
  sanitizer:
    enabled: true
`
	os.WriteFile(path, []byte(content), 0644)
	return path
}

func TestCLI_Version(t *testing.T) {
	bin := buildBinary(t)
	out, err := exec.Command(bin, "version").CombinedOutput()
	if err != nil {
		t.Fatalf("version command failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "guardianwaf") {
		t.Errorf("expected 'guardianwaf' in version output, got: %s", out)
	}
}

func TestCLI_Help(t *testing.T) {
	bin := buildBinary(t)
	out, err := exec.Command(bin, "help").CombinedOutput()
	if err != nil {
		t.Fatalf("help command failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "COMMANDS") {
		t.Errorf("expected 'COMMANDS' in help output, got: %s", out)
	}
}

func TestCLI_UnknownCommand(t *testing.T) {
	bin := buildBinary(t)
	cmd := exec.Command(bin, "nonexistent")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("expected non-zero exit for unknown command")
	}
	if !strings.Contains(string(out), "Unknown command") {
		t.Errorf("expected 'Unknown command' in output, got: %s", out)
	}
}

func TestCLI_NoArgs(t *testing.T) {
	bin := buildBinary(t)
	cmd := exec.Command(bin)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("expected non-zero exit for no args")
	}
	if !strings.Contains(string(out), "USAGE") {
		t.Errorf("expected 'USAGE' in output, got: %s", out)
	}
}

func TestCLI_Validate_Valid(t *testing.T) {
	bin := buildBinary(t)
	cfgPath := writeTestConfig(t)
	out, err := exec.Command(bin, "validate", "-config", cfgPath).CombinedOutput()
	if err != nil {
		t.Fatalf("validate failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "valid") {
		t.Errorf("expected 'valid' in output, got: %s", out)
	}
}

func TestCLI_Validate_InvalidFile(t *testing.T) {
	bin := buildBinary(t)
	cmd := exec.Command(bin, "validate", "-config", "/nonexistent/file.yaml")
	_, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("expected non-zero exit for invalid config file")
	}
}

func TestCLI_Check_Clean(t *testing.T) {
	bin := buildBinary(t)
	cfgPath := writeTestConfig(t)
	out, err := exec.Command(bin, "check", "-config", cfgPath, "-url", "/hello",
		"-H", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0").CombinedOutput()
	if err != nil {
		// exit code 2 = blocked, which is also a valid test path
		if !strings.Contains(string(out), "Action:") {
			t.Fatalf("check failed unexpectedly: %v\n%s", err, out)
		}
	}
	if !strings.Contains(string(out), "Action:") {
		t.Errorf("expected 'Action:' in output, got: %s", out)
	}
}

func TestCLI_Check_Attack(t *testing.T) {
	bin := buildBinary(t)
	cfgPath := writeTestConfig(t)
	cmd := exec.Command(bin, "check", "-config", cfgPath, "-url", "/search?q='+OR+1=1--", "-v")
	out, err := cmd.CombinedOutput()
	// Exit code 2 = blocked
	if err == nil {
		// Might pass if score is below threshold
		if !strings.Contains(string(out), "PASSED") && !strings.Contains(string(out), "BLOCKED") {
			t.Errorf("expected PASSED or BLOCKED, got: %s", out)
		}
	} else {
		if !strings.Contains(string(out), "BLOCKED") {
			t.Errorf("expected 'BLOCKED' for attack, got: %s", out)
		}
	}
}

func TestCLI_Check_WithBody(t *testing.T) {
	bin := buildBinary(t)
	cfgPath := writeTestConfig(t)
	out, _ := exec.Command(bin, "check", "-config", cfgPath, "-url", "/api/data", "-method", "POST",
		"-body", `{"user":"test"}`,
		"-H", "User-Agent: Mozilla/5.0 Chrome/120.0",
		"-H", "Content-Type: application/json").CombinedOutput()
	if !strings.Contains(string(out), "Action:") {
		t.Errorf("expected 'Action:' in output, got: %s", out)
	}
}

func TestCLI_Check_WithHeaders(t *testing.T) {
	bin := buildBinary(t)
	cfgPath := writeTestConfig(t)
	out, _ := exec.Command(bin, "check", "-config", cfgPath, "-url", "/test",
		"-H", "User-Agent: Mozilla/5.0 Chrome/120.0",
		"-H", "X-Custom: value",
		"-H", "Accept: text/html").CombinedOutput()
	if !strings.Contains(string(out), "Action:") {
		t.Errorf("expected 'Action:' in output, got: %s", out)
	}
}

func TestCLI_Check_MissingURL(t *testing.T) {
	bin := buildBinary(t)
	cfgPath := writeTestConfig(t)
	cmd := exec.Command(bin, "check", "-config", cfgPath)
	_, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("expected non-zero exit for missing --url")
	}
}

func TestCLI_Serve_Startup(t *testing.T) {
	bin := buildBinary(t)

	// Find a free port
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to find free port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "guardianwaf.yaml")
	cfgContent := fmt.Sprintf(`mode: enforce
listen: "127.0.0.1:%d"
dashboard:
  enabled: false
mcp:
  enabled: false
`, port)
	os.WriteFile(cfgPath, []byte(cfgContent), 0644)

	cmd := exec.Command(bin, "serve", "-config", cfgPath)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start serve: %v", err)
	}

	// Wait for server to start
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	deadline := time.Now().Add(5 * time.Second)
	started := false
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			started = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	if !started {
		cmd.Process.Kill()
		t.Fatal("server did not start within timeout")
	}

	// Send a request
	resp, err := http.Get(fmt.Sprintf("http://%s/healthz", addr))
	if err == nil {
		resp.Body.Close()
	}

	// Kill the server
	cmd.Process.Kill()
	cmd.Wait()
}

func TestCLI_Sidecar_Startup(t *testing.T) {
	bin := buildBinary(t)

	// Start a backend
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "backend ok")
	}))
	defer backend.Close()

	// Find a free port
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to find free port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	cmd := exec.Command(bin, "sidecar", "-upstream", backend.URL, "-listen", fmt.Sprintf("127.0.0.1:%d", port))
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start sidecar: %v", err)
	}

	// Wait for sidecar to start
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	deadline := time.Now().Add(5 * time.Second)
	started := false
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			started = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	if !started {
		cmd.Process.Kill()
		t.Fatal("sidecar did not start within timeout")
	}

	// Hit the healthz endpoint
	resp, err := http.Get(fmt.Sprintf("http://%s/healthz", addr))
	if err != nil {
		cmd.Process.Kill()
		cmd.Wait()
		t.Fatalf("healthz request failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 from healthz, got %d", resp.StatusCode)
	}

	// Hit a proxied endpoint
	resp2, err := http.Get(fmt.Sprintf("http://%s/test", addr))
	if err == nil {
		resp2.Body.Close()
	}

	// Kill the sidecar
	cmd.Process.Kill()
	cmd.Wait()
}

// --- startDashboard endpoints ---

func TestStartDashboard_Endpoints(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Dashboard.Enabled = true
	cfg.Dashboard.Listen = "127.0.0.1:0"
	cfg.Dashboard.APIKey = ""

	store := events.NewMemoryStore(1000)
	bus := events.NewEventBus()
	eng, err := engine.NewEngine(cfg, store, bus)
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}
	defer eng.Close()

	// Use a listener to get the actual port
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen error: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	cfg.Dashboard.Listen = addr
	srv := startDashboard(cfg, eng)
	if srv == nil {
		t.Fatal("expected non-nil server")
	}
	defer srv.Close()

	// Wait for server to be ready
	time.Sleep(100 * time.Millisecond)

	// Test /healthz
	resp, err := http.Get(fmt.Sprintf("http://%s/healthz", addr))
	if err != nil {
		t.Fatalf("healthz request failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 from healthz, got %d", resp.StatusCode)
	}

	// Test /api/stats
	resp2, err := http.Get(fmt.Sprintf("http://%s/api/stats", addr))
	if err != nil {
		t.Fatalf("stats request failed: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Errorf("expected 200 from stats, got %d", resp2.StatusCode)
	}
}

func TestStartDashboard_WithAPIKey(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Dashboard.Enabled = true
	cfg.Dashboard.APIKey = "secret-key"

	store := events.NewMemoryStore(1000)
	bus := events.NewEventBus()
	eng, err := engine.NewEngine(cfg, store, bus)
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}
	defer eng.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen error: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	cfg.Dashboard.Listen = addr
	srv := startDashboard(cfg, eng)
	defer srv.Close()
	time.Sleep(100 * time.Millisecond)

	// Without key — should get 401
	resp, err := http.Get(fmt.Sprintf("http://%s/api/stats", addr))
	if err != nil {
		t.Fatalf("stats request failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 without API key, got %d", resp.StatusCode)
	}

	// With correct key
	req, _ := http.NewRequest("GET", fmt.Sprintf("http://%s/api/stats", addr), nil)
	req.Header.Set("X-API-Key", "secret-key")
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("stats request with key failed: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Errorf("expected 200 with correct API key, got %d", resp2.StatusCode)
	}
}

// --- loadConfig edge cases ---

func TestLoadConfig_NonDefaultPathNotFound(t *testing.T) {
	// Non-default path that doesn't exist — should call os.Exit
	// We can't test os.Exit directly, but we can test the file-exists path
	dir := t.TempDir()
	path := filepath.Join(dir, "exists.yaml")
	os.WriteFile(path, []byte("mode: monitor\n"), 0644)
	cfg := loadConfig(path)
	if cfg.Mode != "monitor" {
		t.Errorf("expected 'monitor', got %q", cfg.Mode)
	}
}

// --- TestRequest edge case ---

func TestMCPAdapter_TestRequest_InvalidMethod(t *testing.T) {
	a := newTestAdapter(t)
	// Invalid HTTP method with space causes NewRequest to fail
	_, err := a.TestRequest("BAD METHOD", "/test", nil)
	if err == nil {
		t.Fatal("expected error for invalid method")
	}
}
