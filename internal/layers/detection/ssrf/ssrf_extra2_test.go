package ssrf

import (
	"strings"
	"testing"
)

func TestExtractContext_LongResultTruncated(t *testing.T) {
	// Use a very long pattern so the context window exceeds 200 chars
	prefix := strings.Repeat("a", 50)
	pattern := strings.Repeat("b", 200)
	suffix := strings.Repeat("c", 50)
	input := prefix + pattern + suffix

	ctx := extractContext(input, pattern)
	if len(ctx) != 200 {
		t.Errorf("expected context length 200, got %d", len(ctx))
	}
	if !strings.HasSuffix(ctx, "...") {
		t.Error("expected truncated context to end with ...")
	}
}
