# Open Redirect Security Scan Results

**Scanner:** sc-open-redirect
**Target:** GuardianWAF (internal/dashboard/, internal/layers/response/, internal/proxy/, cmd/guardianwaf/)
**Date:** 2026-04-16

---

## Findings Summary

| Finding | Severity | Confidence | Status |
|---------|----------|------------|--------|
| REDIR-001 Protocol-relative URI bypass in HTTP redirect | Low | 45 | Informational |

**Total Findings:** 1

---

## Detailed Findings

### REDIR-001: Protocol-relative URI bypass in HTTP redirect handler

**Severity:** Low
**Confidence:** 45/100
**File:** `cmd/guardianwaf/main.go:1072-1082`, `cmd/guardianwaf/main_default.go:1003-1009`
**Vulnerability Type:** CWE-601 (Open Redirect)

**Description:**

The HTTP-to-HTTPS redirect handler constructs the redirect target as `https://" + host + uri` where `host` is validated against configured virtual hosts but `uri` is used directly from `r.URL.RequestURI()`. While the URI is checked for a `//` prefix at the path level (`strings.HasPrefix(uri, "//")`), a query parameter value containing `//` (e.g., `?redirect=//evil.com`) is not caught by this check.

The attack scenario is constrained:
- `host` must pass validation against `cfg.VirtualHosts` (cannot be arbitrary)
- `uri` query values with `//` pass through since the prefix check only targets `uri` itself
- Combined: `https://legitimate.com?redirect=//evil.com` - the browser may interpret the `//evil.com` query value as a protocol-relative URL depending on HTML5 URL parsing

The Host header sanitization at line 1051 correctly blocks `@` and `/` characters: `strings.ContainsAny(host, "@/")` prevents `https://legitimate.com@evil.com` style attacks. The `//` check at line 1074 only catches `uri` paths starting with `//`, not embedded `//` in query values.

**Impact:**

Limited in practice because:
1. The `host` is restricted to known virtual host domains (not attacker-controlled)
2. An attacker cannot redirect to an arbitrary domain unless they control a configured virtual host domain
3. Even if exploited, the redirect goes to the same domain with a modified query string

**Evidence:**

```go
// main.go:1072-1082
uri := r.URL.RequestURI()
// Prevent open redirect via protocol-relative URLs (//evil.com)
if strings.HasPrefix(uri, "//") {
    uri = "/" + strings.TrimLeft(uri, "/")
}
// ... host validation ...
target := "https://" + host + uri
http.Redirect(w, r, target, http.StatusMovedPermanently)
```

**Remediation:**

Consider also checking query strings for `//` protocol-relative patterns:
```go
uri := r.URL.RequestURI()
if strings.Contains(uri, "//") {
    uri = strings.ReplaceAll(uri, "//", "/")
}
```

Alternatively, use `url.Parse` to properly parse and reconstruct the URL, stripping any scheme-relative components.

**Related Findings:**

All other `http.Redirect` calls in the codebase use hardcoded paths:
- `internal/dashboard/dashboard.go:262,287,291,306,333,447` - all redirect to "/" or "/login" (hardcoded)
- `internal/layers/challenge/challenge.go:168` - redirects to user-supplied `redirect` parameter with proper sanitization (must start with `/`, cannot contain `\\@`, cannot be `//...`)

---

## Excluded (Safe)

| Location | Reason |
|----------|--------|
| `internal/dashboard/dashboard.go` lines 262, 287, 291, 306, 333, 447 | All hardcoded to "/" or "/login" - no user-controlled input |
| `internal/layers/challenge/challenge.go:168` | User-supplied `redirect` properly sanitized: must start with `/`, blocked chars: `\\@`, prevents `//` prefix. Also requires solved PoW + HMAC cookie. |
| `internal/layers/response/` | No redirect handlers found in response layer |

---

## References

- [CWE-601: Open Redirect](https://cwe.mitre.org/data/definitions/601.html)
- [OWASP: Unvalidated Redirects and Forwards](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client_Side_Testing/04-Testing_for_Client_Side_URL_Redirect)
