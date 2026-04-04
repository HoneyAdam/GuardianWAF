package sqli

import (
	"testing"
)

// TestTokenizer_BackslashAtEnd covers the j > n branch in string literal parsing.
func TestTokenizer_BackslashAtEnd(t *testing.T) {
	// Input: 'x\  (3 chars inside the string: apostrophe, x, backslash)
	tokens := Tokenize("'x\\")
	if len(tokens) == 0 {
		t.Fatal("expected at least one token")
	}
	if tokens[0].Type != TokenStringLiteral {
		t.Errorf("expected StringLiteral for quote token, got %v", tokens[0].Type)
	}
}

// TestCheckBooleanInjection_CommentBetweenStringAndOr covers the comment-skip
// branch inside checkBooleanInjection when a comment appears between a string
// literal and the OR/AND operator.
func TestCheckBooleanInjection_CommentBetweenStringAndOr(t *testing.T) {
	tokens := Tokenize("'x'/*c*/OR 1=1")
	findings := checkBooleanInjection(tokens, "query")
	if len(findings) == 0 {
		t.Error("expected boolean injection finding with comment between string and OR")
	}
}

// TestHasTautology_AllCommentsAfterStart covers the branch where the left
// operand cannot be found because all remaining tokens are comments.
func TestHasTautology_AllCommentsAfterStart(t *testing.T) {
	// Need len(tokens) > startIdx+2 so we pass the early guard but then only
	// encounter comments. OR + 3 comments = 4 tokens; startIdx=1 gives 1+2 < 4.
	tokens := Tokenize("OR/*c1*//*c2*//*c3*/")
	result := hasTautology(tokens, 1)
	if result {
		t.Error("expected false when only comments follow OR")
	}
}

// TestHasTautology_AllCommentsAfterLeft covers the operator-not-found branch.
func TestHasTautology_AllCommentsAfterLeft(t *testing.T) {
	tokens := Tokenize("1/*c1*//*c2*//*c3*/")
	result := hasTautology(tokens, 0)
	if result {
		t.Error("expected false when only comments follow left operand")
	}
}

// TestHasTautology_AllCommentsAfterOp covers the right-operand-not-found branch.
func TestHasTautology_AllCommentsAfterOp(t *testing.T) {
	tokens := Tokenize("1=/*c1*//*c2*//*c3*/")
	result := hasTautology(tokens, 0)
	if result {
		t.Error("expected false when only comments follow operator")
	}
}

// TestCheckTimeBasedBlind_WaitforWithComment covers the TokenComment skip
// inside the WAITFOR DELAY search loop.
func TestCheckTimeBasedBlind_WaitforWithComment(t *testing.T) {
	tokens := Tokenize("WAITFOR/*c*/DELAY'0:0:5'")
	findings := checkTimeBasedBlind(tokens, "query")
	hasWaitfor := false
	for _, f := range findings {
		if f.Description == "Time-based blind injection using WAITFOR DELAY" {
			hasWaitfor = true
		}
	}
	if !hasWaitfor {
		t.Error("expected WAITFOR DELAY finding with inline comment")
	}
}

// TestCheckExecString_BreakOnKeyword covers the break branch when the token
// after EXEC is a keyword (not string, other, function, or comment).
func TestCheckExecString_BreakOnKeyword(t *testing.T) {
	tokens := Tokenize("EXEC SELECT")
	_, found := checkExecString(tokens, "query")
	if found {
		t.Error("expected no EXEC finding when keyword follows immediately")
	}
}

// TestCheckExecString_BreakOnOperator covers the break branch when the token
// after EXEC is an operator.
func TestCheckExecString_BreakOnOperator(t *testing.T) {
	tokens := Tokenize("EXEC =")
	_, found := checkExecString(tokens, "query")
	if found {
		t.Error("expected no EXEC finding when operator follows immediately")
	}
}
