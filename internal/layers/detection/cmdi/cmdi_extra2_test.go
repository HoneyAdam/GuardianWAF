package cmdi

import (
	"strings"
	"testing"
)

func TestExtractContext_LongPattern(t *testing.T) {
	pattern := strings.Repeat("b", 200)
	prefix := strings.Repeat("a", 50)
	suffix := strings.Repeat("c", 50)
	input := prefix + pattern + suffix
	ctx := extractContext(input, pattern)
	if !strings.HasSuffix(ctx, "...") {
		t.Error("expected truncated context")
	}
}
