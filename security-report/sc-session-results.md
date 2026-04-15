# Session Management Security Scan Results

**Scanner:** sc-session (security-check)
**Target:** GuardianWAF - Pure Go WAF Codebase
**Date:** 2026-04-15
**Files Scanned:**
- `internal/dashboard/auth.go`
- `internal/layers/zerotrust/service.go`
- `internal/layers/zerotrust/middleware.go`
- `internal/dashboard/dashboard.go`

---

## Summary

| Check | Status | Severity |
|-------|--------|----------|
| Session Fixation | PASS | - |
| Session Hijacking | FAIL | MEDIUM |
| Session Timeout | PASS | - |
| Session Invalidation | FAIL | MEDIUM |
| Concurrent Sessions | WARN | LOW |
| Session Cookies | PASS | - |
| Session ID Generation | PASS | INFO |

---

## Findings

### [MEDIUM] Session Not Invalidated Server-Side on Logout

- **Category:** Session Management
- **Location:** `internal/dashboard/dashboard.go:389` (handleLogout)
- **Description:** The logout handler only clears the session cookie client-side by setting `MaxAge: -1` and an empty value. The session token remains valid on the server. If an attacker has captured the session token before logout, they can continue using it to authenticate.

```go
http.SetCookie(w, &http.Cookie{
    Name:     sessionCookieName,
    Value:    "",
    Path:     "/",
    MaxAge:   -1,  // Only deletes cookie client-side
    HttpOnly: true,
    Secure:   true,
    SameSite: http.SameSiteStrictMode,
})
http.Redirect(w, r, "/login", http.StatusFound)
```

- **Remediation:** Implement server-side session invalidation by maintaining a session invalidation list (e.g., revoked tokens set) or using a session store that supports active invalidation. On logout, add the session token to a revocation list that `verifySession()` checks before validating.

---

### [MEDIUM] Session Token Replay Possible After Logout

- **Category:** Session Management
- **Location:** `internal/dashboard/auth.go:60-69` (signSession), `internal/dashboard/auth.go:72-105` (verifySession)
- **Description:** The dashboard session uses an HMAC-signed token format `timestamp.created.signature` without a server-side session store. Since logout does not invalidate sessions server-side and there is no session revocation list, a captured session token remains valid until its absolute expiry (7 days).

- **Remediation:** Maintain a server-side session registry with active/invalid status. Alternatively, implement token binding using a fast-expiring refresh token pattern where logout immediately revokes the refresh token.

---

### [LOW] No Enforcement of Single Concurrent Session Per User

- **Category:** Session Management
- **Location:** `internal/dashboard/auth.go` (session management)
- **Description:** There is no mechanism to limit concurrent sessions per user/account. The same user can authenticate from multiple devices/browsers simultaneously, and all sessions remain valid. While not inherently insecure, some security policies require single-session enforcement to detect credential sharing or compromise.

- **Remediation:** If single-session-per-user is required, maintain a session registry mapping users to their active session IDs. On new login, invalidate previous sessions for that user.

---

### [INFO] Session Token Uses HMAC Signature Rather Than Random Session ID

- **Category:** Session Management
- **Location:** `internal/dashboard/auth.go:62-68`
- **Description:** The dashboard session token is constructed as `timestamp.created.signature` where signature is an HMAC of the timestamp and client IP. This is cryptographically sound but relies on timestamp uniqueness for replay prevention within the same second (`ts := fmt.Sprintf("%d.%d", now, now)` - both values are identical).

- **Positive:** The HMAC binding to client IP prevents session cookie theft across different clients.
- **Note:** Zero Trust service (`internal/layers/zerotrust/service.go:368-374`) correctly uses `crypto/rand` with 16 random bytes for session ID generation.

---

## Passed Checks

### Session Fixation - PASS
Session IDs are server-generated via `signSession()`. Attackers cannot pre-set or influence session IDs.

### Session Timeout - PASS
- Sliding window: 24 hours (`sessionMaxAge`)
- Absolute maximum: 7 days (`sessionAbsMaxAge`)

### Session Cookies - PASS
All security attributes properly configured:
- `HttpOnly: true` - Prevents JavaScript access
- `Secure: true` - Requires TLS
- `SameSite: http.SameSiteStrictMode` - CSRF protection
- `MaxAge: int(sessionMaxAge.Seconds())` - Client-side expiry

### Session ID Generation (Zero Trust) - PASS
Uses `crypto/rand` with 16 random bytes (128-bit entropy).

---

## Recommendations

1. **High Priority:** Implement server-side session revocation for dashboard logout
2. **Medium Priority:** Add session registry for tracking active sessions per user
3. **Low Priority:** Consider switching dashboard session tokens to random UUIDs with server-side validation (similar to Zero Trust implementation)
