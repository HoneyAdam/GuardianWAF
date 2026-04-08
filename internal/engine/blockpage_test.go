package engine

import (
	"strings"
	"testing"
)

func TestItoa(t *testing.T) {
	tests := []struct {
		input    int
		expected string
	}{
		{0, "0"},
		{1, "1"},
		{9, "9"},
		{10, "10"},
		{42, "42"},
		{100, "100"},
		{999, "999"},
		{1024, "1024"},
		{65535, "65535"},
		{-1, "-1"},
		{-42, "-42"},
		{-100, "-100"},
	}

	for _, tt := range tests {
		result := itoa(tt.input)
		if result != tt.expected {
			t.Errorf("itoa(%d) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestItoa_LargeNumbers(t *testing.T) {
	tests := []struct {
		input    int
		expected string
	}{
		{1000000, "1000000"},
		{2147483647, "2147483647"}, // max int32
	}

	for _, tt := range tests {
		result := itoa(tt.input)
		if result != tt.expected {
			t.Errorf("itoa(%d) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestBlockPage(t *testing.T) {
	requestID := "test-123-abc"
	score := 75

	html := blockPage(requestID, score)

	// Verify basic structure
	if !strings.Contains(html, "<!DOCTYPE html>") {
		t.Error("Missing DOCTYPE")
	}
	if !strings.Contains(html, "GuardianWAF") {
		t.Error("Missing GuardianWAF branding")
	}
	if !strings.Contains(html, "403") {
		t.Error("Missing 403 status code")
	}
	if !strings.Contains(html, "Request Blocked") {
		t.Error("Missing 'Request Blocked' message")
	}
	if !strings.Contains(html, requestID) {
		t.Errorf("Missing request ID: %s", requestID)
	}
	if !strings.Contains(html, "75/100") {
		t.Error("Missing threat score")
	}
}

func TestBlockPage_NoScore(t *testing.T) {
	requestID := "test-456-def"
	score := 0

	html := blockPage(requestID, score)

	// Should not contain threat score section
	if strings.Contains(html, "Threat Score") {
		t.Error("Should not contain Threat Score when score is 0")
	}

	// Should still contain basic structure
	if !strings.Contains(html, requestID) {
		t.Errorf("Should contain request ID: %s", requestID)
	}
}

func TestBlockPage_HtmlStructure(t *testing.T) {
	html := blockPage("req-id", 50)

	// Check HTML elements
	if !strings.Contains(html, "<html") {
		t.Error("Missing <html> tag")
	}
	if !strings.Contains(html, "</html>") {
		t.Error("Missing </html> closing tag")
	}
	if !strings.Contains(html, "<body") {
		t.Error("Missing <body> tag")
	}
	if !strings.Contains(html, "Protected by GuardianWAF") {
		t.Error("Missing footer")
	}
}

func TestBlockPage_EmptyRequestID(t *testing.T) {
	html := blockPage("", 50)

	if !strings.Contains(html, "Request ID:") {
		t.Error("Should contain Request ID label")
	}
}

func TestBlockPage_NegativeScore(t *testing.T) {
	html := blockPage("test", -1)

	// Should handle negative score without panic
	if !strings.Contains(html, "403") {
		t.Error("Should still render block page")
	}
}

func TestBlockPage_MaxScore(t *testing.T) {
	html := blockPage("test", 100)

	if !strings.Contains(html, "100/100") {
		t.Error("Should contain max threat score")
	}
}
