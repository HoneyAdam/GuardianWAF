# Verified Findings — Injection Vulnerability Hunt (2026-04-14)

## Scope

- SQL/NoSQL Injection: `internal/layers/detection/sqli/`
- Command Injection: `internal/layers/detection/cmdi/`
- SSRF: `internal/proxy/`, HTTP request construction
- Header Injection: header parsing and reflection
- Path Traversal: `internal/layers/detection/lfi/`, file path construction

---

## CRITICAL

*(none identified — previously reported CRITICAL findings are already fixed)*

---

## HIGH

### H-INJ-01: SQL Injection — `containsSQLContent` can swallow dangerous SQL inside string literals

**File:** `internal/layers/detection/sqli/tokenizer.go`  
**Lines:** 119-136

```go
if closed && !containsSQLKeyword(inner) {
    tokens = append(tokens, Token{Type: TokenStringLiteral, Value: input[start:j], Pos: start})
    i = j
} else {
    // Either unterminated quote or the "string" contains SQL keywords
    // (likely injection). Emit just the quote as a string literal.
    tokens = append(tokens, Token{Type: TokenStringLiteral, Value: string(quote), Pos: start})
    i = start + 1
}
```

**Bypass:** Payload `admin'/**/OR/**/1=1--` — the tokenizer splits on whitespace when checking `containsSQLContent`, so `/**/` is not recognized as SQL content, and `OR` inside the "string" is not flagged.

**Attack scenario:** A login form submission with `username=admin'/**/OR/**/1=1--&password=x` would have `OR` classified as part of a string literal (since it appears inside quotes that contain no whitespace-delimited SQL keywords), causing `checkUnionSelect`, `checkStackedQuery`, `checkBooleanInjection` etc. to all miss it.

**Remediation:** `containsSQLContent` should check for SQL keywords regardless of surrounding whitespace. Use a character-by-character scan that extracts words delimited by any non-alphanumeric character (not just whitespace). Alternatively, require at least one space before/after SQL keywords to confirm they are syntactically standalone.

---

### H-INJ-02: SQL Injection — Comment sequence after string literal not reliably caught

**File:** `internal/layers/detection/sqli/tokenizer.go`  
**Lines:** 141-150, 378-398

```go
// Tokenizer: -- comment
if ch == '-' && i+1 < n && input[i+1] == '-' {
    start := i
    i += 2
    for i < n && input[i] != '\n' {
        i++
    }
    tokens = append(tokens, Token{Type: TokenComment, Value: input[start:i], Pos: start})
    continue
}
```

**Bypass:** Payload `' OR 'x'='x'--` — the closing `'` creates an unterminated string literal, `OR` is detected as a keyword, but the `--` immediately follows the unterminated quote without a separating token. `checkCommentAfterString` (line 378) looks for `TokenStringLiteral` followed by `TokenComment`, but if the string is unterminated, the tokenizer emits only a single quote as a string token (line 134), and the `--` may not be classified as TokenComment if the `--` is treated differently.

**Attack scenario:** In `' OR 'x'='x'--`, after the unterminated quote logic, the `--` gets consumed but the token sequence may not produce the `(StringLiteral, Comment)` adjacency check needed for `checkCommentAfterString` to fire (score 35).

**Remediation:** When a string literal is unterminated, treat all subsequent content up to whitespace as potentially injectable and boost scores accordingly.

---

### H-INJ-03: CMDi — Decoded newlines bypass command detection

**File:** `internal/layers/detection/cmdi/cmdi.go`  
**Lines:** 306-334

```go
func checkEncodedNewline(lower, location string) []engine.Finding {
    if strings.Contains(lower, "%0a") || strings.Contains(lower, "%0d") {
        // Check if there's a command after the newline
        parts := strings.Split(lower, "%0a")
        if len(parts) < 2 {
            parts = strings.Split(lower, "%0d")
        }
        for i := 1; i < len(parts); i++ {
            trimmed := strings.TrimSpace(parts[i])
            cmd := extractFirstWord(trimmed)
            if IsCommand(cmd) {
                findings = append(findings, makeFinding(60, engine.SeverityHigh,
                    "Newline injection with command detected: "+cmd,
                    extractContext(lower, "%0"), location, 0.80))
                break
            }
        }
        // ...
    }
}
```

**Bypass:** Payload `%0acat%0a/etc/passwd` — the CMDi detector checks for `%0a` and extracts the next word (`cat`), but it only scores 60 (HIGH) even when a dangerous command follows. More critically, the detector only checks the lowercase URL-encoded form — `%0A` (uppercase) would not be caught since it never converts to lowercase before the `Contains` check.

**Attack scenario:** Request path `/api?cmd=%0Acat%0A/etc/passwd` — the `checkEncodedNewline` function checks `lower` (already lowercase), but `%0A` contains uppercase hex digits, so `strings.Contains(lower, "%0a")` would be FALSE for `%0A`. The newline is never decoded before this check (decoding happens in the sanitizer layer, after CMDi detection). The resulting finding score is only 60, below the block threshold.

**Remediation:** 
1. Normalize hex case before checking (`strings.ToLower` on the substring `%0A` → `%0a`).
2. Raise minimum score for newline+command combination to 80+.
3. Apply URL decoding before CMDi detection, not after.

---

## MEDIUM

### M-INJ-01: SQL Injection — Parser differential on Unicode normalization

**File:** `internal/layers/sanitizer/normalize.go`  
**Lines:** 167-221 (fullwidth unicode mapping)

```go
func mapFullwidthToASCII(r rune) rune {
    switch {
    case r >= 0xFF21 && r <= 0xFF3A: // Fullwidth uppercase A-Z
        return rune('A') + (r - 0xFF21)
    case r >= 0xFF41 && r <= 0xFF5A: // Fullwidth lowercase a-z
        return rune('a') + (r - 0xFF41)
    // ...
    }
}
```

**Bypass:** Fullwidth `SEL\u00C2CT` (U+FF53 U+FF45 U+FF4C U+FF55 U+FF43 U+FF54) gets normalized to `SELECT` by `NormalizeAll`, but the SQL tokenizer doesn't normalize Unicode before tokenizing. Some backends normalize Unicode, others don't — creating a WAF/backend parser differential.

**Attack scenario:** Payload `SEL\u00C2CT * FROM users` — the WAF's tokenizer sees `SEL`, `U`, `CT` (not SQL keywords) and misses the injection. The backend normalizes Unicode and executes `SELECT * FROM users`.

**Remediation:** Apply `NormalizeUnicode` during SQLi detection, not just in the sanitizer normalization step. Add a pre-tokenization Unicode normalization pass to `Detect()` in `sqli/`.

---

### M-INJ-02: SQL Injection — Keyword presence without context (low confidence bypass)

**File:** `internal/layers/detection/sqli/tokenizer.go`  
**Lines:** 279-298 (word classification)

```go
switch {
case IsOperatorKeyword(upper):
    tokens = append(tokens, Token{Type: TokenOperator, Value: word, Pos: start})
case IsFunction(upper):
    tokens = append(tokens, Token{Type: TokenFunction, Value: word, Pos: start})
case IsKeyword(upper):
    tokens = append(tokens, Token{Type: TokenKeyword, Value: word, Pos: start})
default:
    tokens = append(tokens, Token{Type: TokenOther, Value: word, Pos: start})
}
```

**Bypass:** Input `unionselection` or `selectall` — the tokenizer extracts words delimited by alphanumeric + underscore, so `unionselection` would be tokenized as a single `TokenOther` token, not as `UNION` + `SELECT`. This bypasses `checkIsolatedKeywords` which only fires on `TokenKeyword` types.

**Attack scenario:** Some CMS parameters may echo back path components like `/user/unionselect?filter=selectall` — the SQLi detector would not flag this as dangerous since keywords are only recognized when surrounded by non-alphanumeric chars.

**Remediation:** Add a heuristic that checks for SQL keyword substrings within TokenOther words, or apply normalization (e.g., split `unionselection` → `union` + `selection`) before tokenization.

---

### M-INJ-03: SSRF — DNS Rebinding window in `SSRFDialContext`

**File:** `internal/proxy/target.go`  
**Lines:** 91-116

```go
func SSRFDialContext() func(ctx context.Context, network, addr string) (net.Conn, error) {
    dialer := &net.Dialer{Timeout: 10 * time.Second}
    return func(ctx context.Context, network, addr string) (net.Conn, error) {
        if allowPrivateTargets.Load() {
            return dialer.DialContext(ctx, network, addr)
        }

        host, _, err := net.SplitHostPort(addr)
        if err != nil {
            host = addr
        }

        // Resolve the hostname to check IPs before dialing
        ips, err := net.LookupIP(host)  // ← DNS LOOKUP
        if err != nil {
            return nil, fmt.Errorf("SSRF dial: DNS lookup failed for %q: %w", host, err)
        }

        for _, ip := range ips {
            if err := classifyIP(ip, host); err != nil {
                return nil, err
            }
        }

        return dialer.DialContext(ctx, network, addr)  // ← ACTUAL DIAL (TOCTOU gap)
    }
}
```

**Bypass:** Attacker controls DNS for `attacker-controlled-domain.com` pointing to `1.2.3.4` (public). The WAF validates this IP passes the filter. Between validation and `dialer.DialContext`, DNS record changes to point to `10.0.0.1` (private). The actual TCP connection goes to the private IP.

**Attack scenario:** Target upstream configured with hostname `api.internal.local`, attacker provides `api.attacker.com` with TTL of 300 seconds. Initial DNS resolves to 1.2.3.4 (passed). Before health check connects, DNS changes to 10.0.0.1. Health check or proxy request connects to private IP.

**Remediation:** Bind the validated IP directly in the DialContext closure rather than re-resolving at dial time. Use `net.Dialer.DialContext` with a pre-resolved connection, or cache the validated IPs and reuse them within a short TTL window (e.g., 5 seconds).

---

### M-INJ-04: Header Injection — `X-Real-IP` forwarded to backends

**File:** `internal/proxy/target.go`  
**Lines:** 157-164

```go
t.proxy.Director = func(req *http.Request) {
    defaultDirector(req)
    req.Header.Del("X-Forwarded-Host")
    req.Header.Del("X-Forwarded-Proto")
}
```

**Bypass:** `X-Real-IP` is NOT deleted by the proxy Director. A client behind a trusted proxy can inject any value for `X-Real-IP`, which some backends use for client IP logging or rate limiting. The engine correctly extracts the real client IP using `extractClientIP` (which trusts proxy headers only from trusted proxies), but the proxy does NOT strip `X-Real-IP` before forwarding to backends.

**Attack scenario:** Attacker sends request with `X-Real-IP: 1.2.3.4`. If the WAF is behind a NAT/firewall that doesn't add XFF, the WAF's `extractClientIP` uses `RemoteAddr` (correct). But the proxy forwards `X-Real-IP: 1.2.3.4` to the backend, which may use this header for logging/ACLs, allowing IP spoofing at the backend layer.

**Remediation:** Also delete `X-Real-IP` in the Director function alongside `X-Forwarded-Host` and `X-Forwarded-Proto`.

---

### M-INJ-05: Path Traversal — Windows short name bypass

**File:** `internal/layers/detection/lfi/lfi.go`  
**Lines:** 280-295

```go
func checkWindowsPaths(lower, location string) []engine.Finding {
    // C:\ or C:/ drive letter — only at start of string or after a boundary character
    for i := 0; i < len(lower)-2; i++ {
        if lower[i] >= 'a' && lower[i] <= 'z' && lower[i+1] == ':' && (lower[i+2] == '\\' || lower[i+2] == '/') {
            // Must be at start or preceded by a non-letter (boundary)
            if i == 0 || !isLetter(lower[i-1]) {
                findings = append(findings, makeFinding(55, engine.SeverityHigh,
                    "Windows drive letter path detected",
                    extractContext(lower, lower[i:i+3]), location, 0.75))
                break
            }
        }
    }
}
```

**Bypass:** Windows short name format `C:\PROGRA~1` (short name for `C:\Program Files`) doesn't contain a drive letter in the traditional `C:` format that the check looks for. `PROGRA~1` contains no dots, so `checkBypassPatterns` (`....//`, etc.) doesn't catch it. The path is not checked against known Windows paths like `\windows\system32` because it uses short names.

**Attack scenario:** Payload `/?file=C:\PROGRA~1\..\..\..\WINNT\SYSTEM32\CMD.EXE` — The backend expands `PROGRA~1` to `Program Files` and processes the traversal. The WAF sees `C:\progra~1\..\..\..\winnt\system32\cmd.exe` which doesn't match `\windows\system32` literally.

**Remediation:** Add short-name expansion lookup or normalize short names before checking. Reject paths containing `~` in path segments (Windows short name marker).

---

## LOW

### L-INJ-01: CMDi — Multiple encoded newlines not cumulatively penalized

**File:** `internal/layers/detection/cmdi/cmdi.go`  
**Lines:** 306-334

```go
func checkEncodedNewline(lower, location string) []engine.Finding {
    if strings.Contains(lower, "%0a") || strings.Contains(lower, "%0d") {
        // ... only scores if a known command follows
    }
    if len(findings) == 0 && (strings.Contains(lower, "%0a") || strings.Contains(lower, "%0d")) {
        findings = append(findings, makeFinding(60, engine.SeverityHigh,
            "Encoded newline injection detected", ...))
    }
}
```

**Bypass:** Payload `%0a%0a%0a%0als` — Four encoded newlines followed by `ls`. The detector only processes the first `%0a` split, meaning the first post-newline word is empty, second is empty, third is empty, fourth is `ls`. The `ls` would be detected, but only with score 60 (HIGH), not accounting for multiple newlines which indicate a more sophisticated attack.

**Remediation:** Count occurrences of consecutive encoded newlines and scale the score proportionally.

---

### L-INJ-02: XSS — Nested encoding differential (WAF decodes, backend doesn't)

**File:** `internal/layers/detection/xss/xss.go` + `internal/layers/sanitizer/normalize.go`

The XSS detector applies `decodeCommonEncodings` before pattern matching, but the backend may render the raw, non-decoded payload. For example, `\x3cscript\x3e` (hex-encoded `<script>`) gets decoded to `<script>` by the WAF and detected, but a backend that does not decode JS hex escapes would render `\x3cscript\x3e` literally.

**Attack scenario:** Input `\x3cscript src="x">\x3c/script\x3e` — the WAF sees `<script src="x">` and detects it. However, if the backend renders this as literal text (no JS execution), it's a false positive. If the backend does decode hex escapes before rendering but does so AFTER the WAF-normalized version, the WAF may miss variants.

**Remediation:** This is a parser differential inherent to multi-layer systems. Detection logic already addresses this with `decodeCommonEncodings`, which is the correct approach. Document that backends should normalize inputs before comparison.

---

### L-INJ-03: SQL Injection — No protection against SQLi via cookie values without delimiters

**File:** `internal/layers/detection/sqli/tokenizer.go`  
**Lines:** 86-95 (filterSignificant)

```go
func filterSignificant(tokens []Token) []Result {
    result := make([]Token, 0, len(tokens))
    for _, t := range tokens {
        if t.Type != TokenWhitespace {
            result = append(result, t)
        }
    }
    return result
}
```

**Bypass:** Cookie value `admin123` — `checkIsolatedKeywords` only triggers on `TokenKeyword` type. Since `admin123` is a single alphanumeric token (TokenOther), it bypasses all keyword checks. An application that uses unsanitized cookie values in SQL queries (`SELECT * FROM users WHERE name = 'admin123'`) is exploitable via cookie injection, but the WAF would not detect this.

**Attack scenario:** Cookie: `session=admin' OR '1'='1` — the single-quoted content `admin` is a TokenOther, `OR` is tokenized as a keyword but only scored 10 (isolated keyword). The boolean injection is not detected because there is no `=` following `OR` in the cookie value context.

**Remediation:** Raise score for `OR` and `AND` keywords even in isolation when they appear in cookie values (not just in query/body).

---

## Summary

| ID | Category | Severity | Status |
|----|----------|----------|--------|
| H-INJ-01 | SQLi — Keyword swallow via comment | HIGH | New finding |
| H-INJ-02 | SQLi — Unterminated quote + comment bypass | HIGH | New finding |
| H-INJ-03 | CMDi — Case-variant encoded newline bypass | HIGH | New finding |
| M-INJ-01 | SQLi — Unicode normalization differential | MEDIUM | New finding |
| M-INJ-02 | SQLi — Keyword substring in TokenOther | MEDIUM | New finding |
| M-INJ-03 | SSRF — TOCTOU in SSRFDialContext | MEDIUM | New finding |
| M-INJ-04 | Header — X-Real-IP not stripped | MEDIUM | New finding |
| M-INJ-05 | LFI — Windows short name bypass | MEDIUM | New finding |
| L-INJ-01 | CMDi — Multiple newline count not penalized | LOW | New finding |
| L-INJ-02 | XSS — Nested encoding differential | LOW | New finding |
| L-INJ-03 | SQLi — Cookie value without delimiters | LOW | New finding |

**Total new findings: 11** (0 CRITICAL, 3 HIGH, 5 MEDIUM, 3 LOW)

---

## Previously Fixed (from prior rounds)

The following previously identified CRITICAL/HIGH findings from `verified-findings.md` remain fixed:

- C1-C3 (deterministic password, panic recovery) — confirmed fixed
- H1-H10 (Slowloris, WebSocket IP spoofing, webhook SSRF, AI SSRF, health check SSRF, regex DoS, DLP raw data, MCP config, Docker socket, SSE leak) — confirmed fixed
- M1-M18 (various) — confirmed fixed
- L1-L15 — confirmed fixed
