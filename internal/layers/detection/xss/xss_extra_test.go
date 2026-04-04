package xss

import "testing"

// TestScanTags_EmptyAttributeName covers the branch where an attribute name
// is empty (e.g. "<tag =value>" or "<tag  >").
func TestScanTags_EmptyAttributeName(t *testing.T) {
	tags := scanTags("<div =value>")
	if len(tags) == 0 {
		t.Fatal("expected at least one tag")
	}
	if tags[0].Name != "div" {
		t.Errorf("expected tag name 'div', got %q", tags[0].Name)
	}
}
