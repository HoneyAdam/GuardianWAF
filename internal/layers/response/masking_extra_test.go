package response

import (
	"strings"
	"testing"
)

func TestMaskCreditCards_ValidCard(t *testing.T) {
	// A valid Luhn-passing card number: 4532015112830366
	input := "My card is 4532015112830366"
	got := MaskCreditCards(input)
	want := "My card is ************0366"
	if got != want {
		t.Errorf("MaskCreditCards(%q) = %q, want %q", input, got, want)
	}
}

func TestMaskAPIKeys_LongKey(t *testing.T) {
	input := "api_key=abcdefghijklmnopqrstuvwxyz123456"
	got := MaskAPIKeys(input)
	if got == input {
		t.Error("expected API key to be masked")
	}
	// Should preserve first 4 and last 4
	if !strings.Contains(got, "abcd") || !strings.Contains(got, "3456") {
		t.Errorf("expected prefix/suffix preserved, got %q", got)
	}
}
