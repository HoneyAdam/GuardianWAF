package response

import "testing"

// TestStripStackTraces_EmptyLineInTrace covers the trimmed=="" branch in
// isStackTraceLine by including a blank line inside a Go stack trace.
func TestStripStackTraces_EmptyLineInTrace(t *testing.T) {
	input := `Start
	goroutine 1 [running]:
	main.handler()
		/app/main.go:42 +0x1a3

	More text
	End`
	result := StripStackTraces(input)
	if !contains(result, "Start") || !contains(result, "End") {
		t.Error("surrounding text should be preserved")
	}
	if contains(result, "goroutine") {
		t.Error("stack trace should be stripped")
	}
}

func contains(s, substr string) bool {
	return len(substr) <= len(s) && (s == substr || findSubstr(s, substr))
}

func findSubstr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
