package alerting

import (
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
)

func TestNewEmailTarget(t *testing.T) {
	cfg := config.EmailConfig{
		Name:     "test-email",
		SMTPHost: "smtp.example.com",
		SMTPPort: 587,
		From:     "alerts@example.com",
		To:       []string{"admin@example.com"},
		Cooldown: 2 * time.Minute,
	}

	target := NewEmailTarget(cfg)
	if target == nil {
		t.Fatal("expected non-nil target")
	}
	if target.config.Name != "test-email" {
		t.Errorf("expected name 'test-email', got %s", target.config.Name)
	}
	if target.cooldown != 2*time.Minute {
		t.Errorf("expected cooldown 2m, got %v", target.cooldown)
	}
	if target.lastFire == nil {
		t.Error("expected non-nil lastFire map")
	}
}

func TestNewEmailTarget_DefaultCooldown(t *testing.T) {
	cfg := config.EmailConfig{
		Name:     "test-email",
		SMTPHost: "smtp.example.com",
		SMTPPort: 587,
		From:     "alerts@example.com",
		To:       []string{"admin@example.com"},
		// Cooldown not set
	}

	target := NewEmailTarget(cfg)
	if target.cooldown != 5*time.Minute {
		t.Errorf("expected default cooldown 5m, got %v", target.cooldown)
	}
}

func TestBuildSMTPMessage(t *testing.T) {
	m := &Manager{}
	msg := m.buildSMTPMessage(
		"from@example.com",
		[]string{"to1@example.com", "to2@example.com"},
		"Test Subject",
		"Test body content",
	)

	msgStr := string(msg)
	if msgStr == "" {
		t.Error("expected non-empty message")
	}

	// Check headers
	if !contains(msgStr, "From: from@example.com") {
		t.Error("expected From header")
	}
	if !contains(msgStr, "To: to1@example.com, to2@example.com") {
		t.Error("expected To header")
	}
	if !contains(msgStr, "Subject: Test Subject") {
		t.Error("expected Subject header")
	}
	if !contains(msgStr, "MIME-Version: 1.0") {
		t.Error("expected MIME-Version header")
	}
	if !contains(msgStr, "Content-Type: text/plain") {
		t.Error("expected Content-Type header")
	}
	if !contains(msgStr, "Test body content") {
		t.Error("expected body content")
	}
}

func TestBuildEmailBody_DefaultTemplate(t *testing.T) {
	m := &Manager{}
	event := &engine.Event{
		ID:        "evt-123",
		Timestamp: time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC),
		ClientIP:  "192.168.1.1",
		Method:    "POST",
		Path:      "/api/test",
		Action:    engine.ActionBlock,
		Score:     85,
		UserAgent: "TestAgent/1.0",
		Findings: []engine.Finding{
			{DetectorName: "sqli", Description: "SQL injection detected", Score: 50},
			{DetectorName: "xss", Description: "XSS detected", Score: 35},
		},
	}

	cfg := config.EmailConfig{
		Name: "test",
	}

	body := m.buildEmailBody(cfg, event)

	if body == "" {
		t.Error("expected non-empty body")
	}
	if !contains(body, "evt-123") {
		t.Error("expected event ID in body")
	}
	if !contains(body, "192.168.1.1") {
		t.Error("expected client IP in body")
	}
	if !contains(body, "POST") {
		t.Error("expected method in body")
	}
	if !contains(body, "/api/test") {
		t.Error("expected path in body")
	}
	if !contains(body, "block") {
		t.Error("expected action in body")
	}
	if !contains(body, "85") {
		t.Error("expected score in body")
	}
	if !contains(body, "TestAgent/1.0") {
		t.Error("expected user agent in body")
	}
	if !contains(body, "SQL injection detected") {
		t.Error("expected findings in body")
	}
	if !contains(body, "XSS detected") {
		t.Error("expected XSS finding in body")
	}
}

func TestBuildEmailBody_CustomTemplate(t *testing.T) {
	m := &Manager{}
	event := &engine.Event{
		ID:        "evt-456",
		Timestamp: time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC),
		ClientIP:  "10.0.0.1",
		Method:    "GET",
		Path:      "/admin",
		Action:    engine.ActionChallenge,
		Score:     60,
		UserAgent: "Mozilla/5.0",
	}

	cfg := config.EmailConfig{
		Name:     "test",
		Template: "Alert: {{Action}} from {{ClientIP}} on {{Path}} with score {{Score}}",
	}

	body := m.buildEmailBody(cfg, event)

	expected := "Alert: challenge from 10.0.0.1 on /admin with score 60"
	if body != expected {
		t.Errorf("expected body '%s', got '%s'", expected, body)
	}
}

func TestBuildEmailBody_AllTemplateVars(t *testing.T) {
	m := &Manager{}
	ts := time.Date(2024, 6, 15, 14, 30, 45, 0, time.UTC)
	event := &engine.Event{
		ID:        "evt-789",
		Timestamp: ts,
		ClientIP:  "172.16.0.1",
		Method:    "POST",
		Path:      "/login",
		Action:    engine.ActionBlock,
		Score:     95,
		UserAgent: "Bot/1.0",
	}

	cfg := config.EmailConfig{
		Name:     "test",
		Template: "ID={{EventID}} IP={{ClientIP}} Method={{Method}} Path={{Path}} Action={{Action}} Score={{Score}} Time={{Timestamp}} UA={{UserAgent}}",
	}

	body := m.buildEmailBody(cfg, event)

	if !contains(body, "ID=evt-789") {
		t.Error("expected EventID substitution")
	}
	if !contains(body, "IP=172.16.0.1") {
		t.Error("expected ClientIP substitution")
	}
	if !contains(body, "Method=POST") {
		t.Error("expected Method substitution")
	}
	if !contains(body, "Path=/login") {
		t.Error("expected Path substitution")
	}
	if !contains(body, "Action=block") {
		t.Error("expected Action substitution")
	}
	if !contains(body, "Score=95") {
		t.Error("expected Score substitution")
	}
	if !contains(body, "UA=Bot/1.0") {
		t.Error("expected UserAgent substitution")
	}
}

func TestGetEmailStats(t *testing.T) {
	// Reset stats first
	ResetEmailStats()

	stats := GetEmailStats()
	if stats.Sent != 0 {
		t.Errorf("expected 0 sent, got %d", stats.Sent)
	}
	if stats.Failed != 0 {
		t.Errorf("expected 0 failed, got %d", stats.Failed)
	}
}

func TestResetEmailStats(t *testing.T) {
	// Manually increment stats
	emailSent.Add(5)
	emailFailed.Add(3)

	ResetEmailStats()

	stats := GetEmailStats()
	if stats.Sent != 0 {
		t.Errorf("expected 0 sent after reset, got %d", stats.Sent)
	}
	if stats.Failed != 0 {
		t.Errorf("expected 0 failed after reset, got %d", stats.Failed)
	}
}

func TestEmailStats_Increment(t *testing.T) {
	ResetEmailStats()

	// Simulate sent emails
	emailSent.Add(3)
	emailFailed.Add(1)

	stats := GetEmailStats()
	if stats.Sent != 3 {
		t.Errorf("expected 3 sent, got %d", stats.Sent)
	}
	if stats.Failed != 1 {
		t.Errorf("expected 1 failed, got %d", stats.Failed)
	}
}

func TestBuildEmailBody_EmptyFindings(t *testing.T) {
	m := &Manager{}
	event := &engine.Event{
		ID:        "evt-empty",
		Timestamp: time.Now(),
		ClientIP:  "192.168.1.1",
		Method:    "GET",
		Path:      "/",
		Action:    engine.ActionPass,
		Score:     0,
		UserAgent: "Test",
		Findings:  []engine.Finding{},
	}

	cfg := config.EmailConfig{
		Name: "test",
	}

	body := m.buildEmailBody(cfg, event)

	if body == "" {
		t.Error("expected non-empty body with empty findings")
	}
}

func TestEmailTarget_CooldownCheck(t *testing.T) {
	cfg := config.EmailConfig{
		Name:     "test",
		Cooldown: time.Hour,
	}

	target := NewEmailTarget(cfg)

	// Initially should not be in cooldown
	clientIP := "192.168.1.1"
	if _, ok := target.lastFire.Load(clientIP); ok {
		t.Error("expected no cooldown initially")
	}

	// Simulate firing
	target.lastFire.Store(clientIP, time.Now())

	// Should be in cooldown now
	if last, ok := target.lastFire.Load(clientIP); !ok {
		t.Error("expected cooldown entry after firing")
	} else {
		fireTime := last.(time.Time)
		if time.Since(fireTime) > time.Second {
			t.Error("expected recent fire time")
		}
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && containsSubstr(s, substr))
}

func containsSubstr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
