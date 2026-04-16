# CSRF Security Scan Results

**Scanner:** sc-csrf (Cross-Site Request Forgery)
**Target:** GuardianWAF Dashboard API
**Date:** 2026-04-16

---

## Summary

| Category | Status |
|----------|--------|
| CSRF Tokens | Not present (uses Origin/Referer check instead) |
| SameSite Cookie | `StrictMode` (properly set) |
| GET state changes | Not found |
| Admin routes CSRF | Missing (uses API key auth only) |

---

## Findings

### CSRF-1: Origin/Referer Check (Low Risk)

The dashboard uses `verifySameOrigin()` in `middleware.go` instead of traditional CSRF tokens. This checks the `Origin` header (preferred) or `Referer` header and validates they match the request host.

**Location:** `internal/dashboard/middleware.go:76-106`

```go
func verifySameOrigin(r *http.Request) bool {
    origin := r.Header.Get("Origin")
    if origin != "" {
        u, err := url.Parse(origin)
        if err != nil {
            return false
        }
        return u.Host == r.Host
    }
    referer := r.Header.Get("Referer")
    if referer != "" {
        u, err := url.Parse(referer)
        if err != nil {
            return false
        }
        return u.Host == r.Host
    }
    return false  // No Origin or Referer — rejected
}
```

**Analysis:** This approach is effective against CSRF when:
- Browsers automatically set `Origin` for cross-origin requests
- The dashboard is accessed directly (not via iframe/proxy that strips headers)

**Note:** Requests without Origin or Referer are rejected (line 104-105). This is a conservative default that prevents CSRF but may cause issues in certain proxy scenarios.

### CSRF-2: authWrap Applies CSRF Check (Low Risk)

All protected state-changing endpoints go through `authWrap()` which applies CSRF validation for cookie-authenticated requests.

**Location:** `internal/dashboard/dashboard.go:255-283`

```go
if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions {
    if r.Header.Get("X-API-Key") == "" && !verifySameOrigin(r) {
        writeJSON(w, http.StatusForbidden, map[string]any{"error": "CSRF validation failed"})
        return
    }
}
```

**Key behavior:**
- API key auth (`X-API-Key` header) skips CSRF check (inherently CSRF-safe since browsers can't set custom headers cross-origin)
- Cookie auth requires Origin/Referer validation

### CSRF-3: Admin Routes Missing CSRF Check (Low-Medium Risk)

Admin routes (`/api/admin/*`) use a custom auth wrapper that only checks for admin API key. No CSRF check is applied.

**Location:** `internal/dashboard/tenant_admin_handler.go:28-50`

```go
auth := func(handler http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        if !h.dashboard.isAdminAuthenticated(r) {
            writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized: system admin key required"})
            return
        }
        handler(w, r)
    }
}
```

**Affected endpoints:**
- `POST /api/admin/tenants` - Create tenant
- `PUT /api/admin/tenants/{id}` - Update tenant
- `DELETE /api/admin/tenants/{id}` - Delete tenant
- `POST /api/admin/tenants/{id}/regenerate-key` - Regenerate API key
- `POST /api/admin/tenants/rules` - Add tenant rule
- `PUT /api/admin/tenants/rules/{tenantID}/{ruleID}` - Update tenant rule
- `DELETE /api/admin/tenants/rules/{tenantID}/{ruleID}` - Delete tenant rule
- `POST /api/admin/billing/{tenantID}` - Generate invoice

**Risk:** If an admin is authenticated via cookie (unlikely since admin endpoints use API key only), these endpoints could be CSRF targets. However, admin auth typically uses `X-API-Key` header which is not subject to CSRF.

### CSRF-4: Logout Partial CSRF Check (Low Risk)

Logout handler only checks `Origin` header (not `Referer`) before revoking session.

**Location:** `internal/dashboard/dashboard.go:425-448`

```go
if origin := r.Header.Get("Origin"); origin != "" {
    if !verifySameOrigin(r) {
        http.Error(w, "forbidden", http.StatusForbidden)
        return
    }
}
```

**Analysis:** This means if `Origin` is not present, the request proceeds. However, this is acceptable since:
- `GET /logout` is a safe navigation action
- Session revocation requires valid cookie regardless of CSRF
- The `Referer` is not checked which is a minor gap

### CSRF-5: SameSite Cookie Properly Configured (Good)

Session cookie is set with `SameSite: http.SameSiteStrictMode` which provides strong CSRF protection for cookie-based auth.

**Location:** `internal/dashboard/auth.go:290-298`

```go
http.SetCookie(w, &http.Cookie{
    Name:     sessionCookieName,
    Value:    token,
    Path:     "/",
    HttpOnly: true,
    Secure:   true, // Always require TLS for session cookies
    SameSite: http.SameSiteStrictMode,
    MaxAge:   int(sessionMaxAge.Seconds()),
})
```

---

## Recommendations

| Priority | Finding | Recommendation |
|----------|---------|----------------|
| Low | Admin routes use API key auth only | Consider adding CSRF check to admin routes for defense-in-depth, even though API key auth is CSRF-safe |
| Low | Logout only checks Origin | Add `Referer` check for GET /logout requests for consistency |
| Info | No traditional CSRF tokens | Document that Origin/Referer validation is the CSRF mechanism (not tokens) |
| Info | Content-Security-Policy `form-action 'self'` | CSP header already restricts form targets to same-origin |

---

## Test Coverage

The dashboard tests include CSRF-related test cases:

- `TestCSRFVerification` in `dashboard_test.go` verifies Origin/Referer validation
- `TestLoginLogout` covers login form submission with CSRF check

---

## Risk Assessment

**Overall Risk: LOW**

The dashboard implements CSRF protection via Origin/Referer validation which is effective for the threat model. Traditional CSRF tokens are not used, but the implemented mechanism is considered equivalent for browser-based attacks.

Key mitigating factors:
1. SameSite=Strict cookie prevents cross-origin cookie sending
2. Origin/Referer header validation catches cross-origin state-changing requests
3. API key authentication is inherently CSRF-safe (browsers can't set custom headers)
4. Admin endpoints use API key auth, not cookies
