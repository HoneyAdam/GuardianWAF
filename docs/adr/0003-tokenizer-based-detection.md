# ADR 003: Tokenizer-Based Detection Engine

## Status: Accepted

## Context

WAF detection for SQL injection, XSS, and other attack vectors can use regex patterns or token-based analysis. Regex is simpler but vulnerable to evasion through encoding, whitespace manipulation, and comment injection.

## Decision

Implement detection using tokenizer-based analysis where input is first broken into tokens (keywords, operators, strings, identifiers), then analyzed for attack patterns. Each detector (SQLi, XSS, LFI, CMDi, XXE, SSRF) has its own tokenizer.

## Consequences

**Positive:**
- Resistant to encoding-based evasion (URL encoding, Unicode, HTML entities)
- More accurate scoring — each token can contribute weighted scores
- Fuzz-tested with comprehensive attack samples
- Explainable findings — each match has a specific token and location

**Negative:**
- Higher CPU cost than simple regex matching
- More code per detector (~400-800 lines each)
- Requires ongoing updates for new attack techniques

## Alternatives Considered

- Regex-only detection — rejected due to well-known evasion weaknesses
- libinjection integration — rejected due to ADR 001 (C dependency)
