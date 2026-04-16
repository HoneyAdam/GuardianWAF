# SC-XSS: Cross-Site Scripting Scan Results

**Scanner:** sc-xss (SC: Cross-Site Scripting)
**Target:** GuardianWAF — React Dashboard, XSS Detection Layer, Error Pages
**Date:** 2026-04-16

---

## Summary

**No XSS vulnerabilities found.** The WAF dashboard and all server-side HTML generation correctly escape user-controlled data before rendering.

---

## Area 1: React Dashboard

**Files scanned:** `internal/dashboard/ui/src/`

- `components/dashboard/event-detail.tsx` — SAFE: All fields use React JSX expressions which auto-escape. Finding `matched_value` uses `textContent`.
- `pages/logs.tsx` — SAFE: Log messages use JSX auto-escaping.
- `pages/ai.tsx` — SAFE: All provider/model strings rendered via JSX auto-escaping.
- `pages/config.tsx` — SAFE: All config values rendered via JSX auto-escaping.
- `components/routing/routing-graph.tsx` — SAFE: Uses @xyflow/react, data from typed API responses.

**No dangerouslySetInnerHTML found in any React component.**

---

## Area 2: XSS Detection Layer

**Files scanned:** `internal/layers/detection/xss/patterns.go`

The detector uses defense-in-depth with 14 pattern groups:

1. `<script>...</script>` block (score 95)
2. `<script` tag open (score 90)
3. SVG vectors with event handlers (score 85)
4. Tag+event handler combos (score 85)
5. JavaScript protocol in attributes (score 80)
6. data:text/html URIs (score 75)
7. CSS expression() (score 70)
8. eval() calls (score 65)
9. document.cookie access (score 60)
10. document.write calls (score 55)
11. innerHTML manipulation (score 50)
12. Standalone on[a-z]+= event handlers (score 70)
13. Template injection markers (score 55)
14. Encoded angle bracket bonus (score 20)

Also decodes common encodings (%3c, &#60;, \x3c) before pattern matching — handles evasion.

**No evasion vectors identified.**

---

## Area 3: Error Pages

**Files scanned:** `internal/layers/response/errorpage.go`

Both `productionErrorPage()` and `developmentErrorPage()` use a custom `escapeHTML()` function. All user-controlled content is escaped before insertion:

```go
func escapeHTML(s string) string {
    s = strings.ReplaceAll(s, "&", "&amp;")
    s = strings.ReplaceAll(s, "<", "&lt;")
    s = strings.ReplaceAll(s, ">", "&gt;")
    s = strings.ReplaceAll(s, "\"", "&quot;")
    s = strings.ReplaceAll(s, "'", "&#39;")
    return s
}
```

Details in development mode are also escaped.

**No XSS vectors found.**

---

## Area 4: Challenge Page

**File:** `internal/layers/botdetect/collector_handler.go`

`generateChallengePage()` escapes siteKey with `html.EscapeString()` and validates script URL against an allowlist:

```go
allowedScripts := map[string]bool{
    "https://js.hcaptcha.com/1/api.js":                       true,
    "https://challenges.cloudflare.com/turnstile/v0/api.js":  true,
}
```

**No XSS vectors found.**

---

## Area 5: Login Page

**File:** `internal/dashboard/auth.go`

Error message escaped with `html.EscapeString(errMsg)`.

**No XSS vectors found.**

---

## Area 6: Vanilla JS Dashboard

**File:** `internal/dashboard/static/app.js`

Well-documented `escapeHtml()` function used for all dynamic content:

```javascript
function escapeHtml(str) {
    if (!str) return '';
    return str
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}
```

All event fields use `textContent` (DOM text nodes, not innerHTML).

**No XSS vectors found.**

---

## Conclusion

GuardianWAF is **free of XSS vulnerabilities**. The codebase demonstrates strong security practices:

1. React components — JSX auto-escaping only; no dangerouslySetInnerHTML
2. Go HTML generation — explicit escapeHTML()/html.EscapeString() for all user data
3. XSS detector — 14-pattern coverage with encoding evasion detection
4. Challenge page — siteKey escaped, script URL allowlisted
5. Vanilla JS — documented escapeHtml() for all dynamic content

**No remediation required.**
