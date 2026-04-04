package ssrf

import "testing"

// TestCheckPrivateIPs_PrefixAtEnd covers the hostStart >= len(lower) break
// inside checkPrivateIPs when a URL prefix is at the end of the string.
func TestCheckPrivateIPs_PrefixAtEnd(t *testing.T) {
	findings := checkPrivateIPs("visit http://", "query")
	if len(findings) != 0 {
		t.Error("expected no findings when URL prefix is at end of input")
	}
}

// TestCheckEncodedIPs_PrefixAtEnd covers the hostStart >= len(lower) continue
// inside checkEncodedIPs when a URL prefix is at the end of the string.
func TestCheckEncodedIPs_PrefixAtEnd(t *testing.T) {
	findings := checkEncodedIPs("redirect to https://", "query")
	if len(findings) != 0 {
		t.Error("expected no findings when URL prefix is at end of input")
	}
}
