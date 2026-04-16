# sc-session: Session Management Security Scan

**Scanner:** sc-session
**Target:** `internal/dashboard/auth.go`, `internal/dashboard/dashboard.go`
**Date:** 2026-04-16
**Severity Classification:** Per OWASP Session Management guidelines

---

## Summary

The session management implementation in `auth.go` is **well-designed** with strong cryptographic primitives and multiple defense layers. No critical or high-severity issues were found. One medium-severity finding (SESS-002: missing session regeneration on login) and one informational note (SESS-003: Secure flag behavior) are documented below.

---

## Findings

### SESS-001 — Session Token Generation

**Severity:** Informational (Positive Finding)
**Confidence:** 100
**File:** `internal/dashboard/auth.go:44-56, 76-83`

**Analysis:**
- Tokens are signed using HMAC-SHA256 with a 32-byte secret generated via `crypto/rand` at startup
- `init()` fails the process if `crypto/rand` is unavailable (fail-secure design)
- `SetSessionSecret()` allows persistent secrets via config, with hex-decoding and SHA256 fallback
- Token format: `timestamp.creation_timestamp.signature` where `signature = HMAC-SHA256(secret, "timestamp.creation_timestamp:clientIP")`
- Client IP is bound into the HMAC, preventing session cookie theft across different IPs

**Verdict:** Cryptographically sound. Token format is non-predictable; the HMAC secret is known only to the server.

---

### SESS-002 — Session Regeneration on Privilege Change

**Severity:** Medium
**Confidence:** 80
**File:** `internal/dashboard/dashboard.go:332`

**Description:**
The login handler calls `setSessionCookie()` directly without first invalidating any pre-existing session. An authenticated session (e.g., from a prior login attempt or shared workstation) retains its token ID after a successful login — the session ID is reused rather than regenerated.

```go
// dashboard.go:298-334
func (d *Dashboard) handleLoginSubmit(...) {
    // ...
    if subtle.ConstantTimeCompare([]byte(key), []byte(d.apiKey)) != 1 {
        d.recordLoginFailure(clientIP)
        // ...
    }
    d.resetLoginAttempts(clientIP)
    setSessionCookie(w, r) // No prior session invalidation; token is set fresh but NOT regenerated
    http.Redirect(w, r, "/", http.StatusFound)
}
```

**Impact:** A session fixation attack is theoretically possible if an attacker can set a known session token on a victim's browser before login. After login, the attacker uses the same token to hijack the session. Requires the attacker to pre-set a cookie on the victim's browser (e.g., via a sub-domain cookie-write or XSS).

**Remediation:**
```go
// In handleLoginSubmit, before calling setSessionCookie:
if cookie, err := r.Cookie(sessionCookieName); err == nil && cookie.Value != "" {
    RevokeSession(cookie.Value) // Invalidate old session before issuing new one
}
```

**CWE:** CWE-384 (Session Fixation)

---

### SESS-003 — Secure Cookie Flag in Development Environments

**Severity:** Low
**Confidence:** 70
**File:** `internal/dashboard/auth.go:295`

**Description:**
`setSessionCookie` unconditionally sets `Secure: true`:

```go
// auth.go:290-298
http.SetCookie(w, &http.Cookie{
    Name:     sessionCookieName,
    // ...
    HttpOnly: true,
    Secure:   true, // Always require TLS for session cookies
    SameSite: http.SameSiteStrictMode,
    MaxAge:   int(sessionMaxAge.Seconds()),
})
```

When the dashboard runs over HTTP (e.g., `http://localhost:9443`), the browser will not store the session cookie because the `Secure` flag prohibits cleartext transport. This can cause confusing auth failures in dev/test setups.

**Impact:** No security impact in production (HTTPS is expected). Development usability issue only.

**Remediation:** Consider a config-driven approach:
```go
Secure: !isDevelopmentEnv(), // Configurable per environment
```

**CWE:** CWE-614 (Sensitive Cookie Without Secure Flag) — note: flag IS set correctly; the finding is about unconditional enforcement.

---

## Cookie Attribute Checklist

| Attribute | Status | Location |
|-----------|--------|----------|
| HttpOnly | ✅ Set | `auth.go:294` |
| Secure | ✅ Set (always) | `auth.go:295` |
| SameSite=Strict | ✅ Set | `auth.go:296` |
| Path=/ | ✅ Set | `auth.go:291` |
| Max-Age (24h) | ✅ Set | `auth.go:297` |

---

## Session Lifecycle Verification

| Feature | Status | Location |
|---------|--------|----------|
| Server-side revocation | ✅ | `auth.go:132-141` (`RevokeSession`) |
| Revocation checked before signature | ✅ | `auth.go:91-94` |
| Logout invalidates session | ✅ | `dashboard.go:434-437` |
| Concurrent session limit (5/IP) | ✅ | `auth.go:25, 146-187` |
| Absolute max lifetime (7 days) | ✅ | `auth.go:24` |
| Sliding idle timeout (24h) | ✅ | `auth.go:22, 117-119` |
| Session bound to client IP | ✅ | `auth.go:76-83, 104-110` |
| Login rate limiting | ✅ | `dashboard.go:310-320, 336-361` |
| CSRF protection on state-changes | ✅ | `dashboard.go:273-279` (via `verifySameOrigin`) |
| Pre-login session invalidation | ❌ Missing | `dashboard.go:332` (see SESS-002) |

---

## Additional Security Controls (Positive Findings)

1. **Origin/Referer CSRF validation** (`middleware.go:76-106`): All non-GET state-changing requests verify Origin or Referer matches request Host. Requests without either are rejected.

2. **API key in query string rejected** (`auth.go:261-265`):
   ```go
   if r.URL.Query().Get("api_key") != "" {
       log.Printf("[WARN] Rejected API key from query parameter ...")
       return false
   }
   ```
   Prevents API key leakage via access logs, browser history, and Referer headers.

3. **Constant-time comparison** for API key validation (`dashboard.go:324`): Uses `subtle.ConstantTimeCompare` to prevent timing attacks.

4. **Login rate limiting** (`dashboard.go:95-103, 336-413`): 5 attempts per 5-minute window, 15-minute lockout. Cleanup goroutine prevents memory growth.

5. **No session token in URL**: Session ID is cookie-only; never appears in query parameters or URL path.

---

## Conclusion

The session management implementation is **robust and secure** for a production WAF dashboard. The only actionable finding is **SESS-002** (session regeneration on login), which should be addressed to fully comply with OWASP session fixation prevention guidelines. **SESS-003** is a development usability note, not a production security defect.

**Risk Level:** Low