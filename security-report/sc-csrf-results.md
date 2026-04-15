# CSRF Security Assessment — GuardianWAF

**Scanner:** sc-csrf
**Target:** GuardianWAF (Pure Go WAF + React Dashboard)
**Date:** 2026-04-15

---

## Summary

No CSRF vulnerabilities found. The implementation uses a defense-in-depth approach combining multiple overlapping safeguards:

- Session cookies use `SameSite=Strict` (cannot be sent cross-origin in any browser)
- `authWrap` middleware enforces `verifySameOrigin` for all state-changing requests authenticated via cookie
- API key header authentication is inherently CSRF-safe (browsers cannot set custom headers cross-origin)
- `verifySameOrigin` validates Origin or Referer header matches the request Host
- GET logout is explicitly allowed with referrer verification only when Origin is present
- No state-changing GET routes exist for sensitive operations

---

## Detailed Findings

### [INFO] Session Cookie Uses SameSite=Strict

- **Category:** Cross-Site Request Forgery
- **Location:** internal/dashboard/auth.go:155
- **Description:** The session cookie is set with `SameSite: http.SameSiteStrictMode`. This is the strongest SameSite level and prevents the cookie from being sent in any cross-origin request, including navigation and subresource requests. CSRF attacks that rely on cookie transmission are fully blocked at the browser level.
- **Remediation:** No action needed. This is the correct configuration.

### [INFO] authWrap Enforces Same-Origin Verification for State-Changing Requests

- **Category:** Cross-Site Request Forgery
- **Location:** internal/dashboard/dashboard.go:236-243
- **Description:** The `authWrap` middleware checks `verifySameOrigin(r)` for all non-idempotent requests (POST, PUT, DELETE, etc.) when authenticated via session cookie. API key authentication bypasses this check, which is correct since browsers cannot set custom headers (X-API-Key) in cross-origin requests. This ensures defense-in-depth even if the SameSite cookie were somehow bypassed.
- **Remediation:** No action needed. This is the correct design.

### [INFO] verifySameOrigin Validates Origin and Referer Headers

- **Category:** Cross-Site Request Forgery
- **Location:** internal/dashboard/middleware.go:76-106
- **Description:** The `verifySameOrigin` function validates that both Origin and Referer headers (when present) match the request Host. Critically, it rejects requests that have neither header, preventing CSRF via stripped headers. The comment explicitly notes this: "Requests without Origin or Referer — reject to prevent CSRF via stripped headers."
- **Remediation:** No action needed. This is the correct implementation.

### [INFO] Login Form CSRF Protected

- **Category:** Cross-Site Request Forgery
- **Location:** internal/dashboard/dashboard.go:263-267
- **Description:** The `handleLoginSubmit` handler calls `verifySameOrigin(r)` before processing credentials, ensuring login attempts originate from the same host. This prevents login CSRF attacks.
- **Remediation:** No action needed.

### [INFO] No State-Changing GET Routes for Sensitive Operations

- **Category:** Cross-Site Request Forgery
- **Location:** internal/dashboard/dashboard.go:124-196
- **Description:** All sensitive operations (rules CRUD, config updates, bans, ACLs, webhooks, alerting) use POST/PUT/DELETE methods. GET routes only read data. The only GET route that changes state is `/logout`, which is acceptable (user-initiated navigation) and has partial origin checking.
- **Remediation:** No action needed.

### [INFO] GET /logout Has Partial CSRF Protection

- **Category:** Cross-Site Request Forgery
- **Location:** internal/dashboard/dashboard.go:389-408
- **Description:** The logout handler only enforces `verifySameOrigin` when the Origin header is present (not Referer alone). Since Origin is stripped on some cross-origin navigations (e.g., redirect chains), a malicious page could potentially trigger logout via a cross-origin redirect. However, logout is a low-impact operation (destroys the session cookie), and the session cookie itself is SameSite=Strict, so any browser-side CSRF attack is already blocked. Additionally, the comment says "GET logout is allowed (user clicking a link)" which is intentional.
- **Remediation:** Consider enforcing Origin check unconditionally, or rely on the SameSite=Strict cookie as the primary defense (which is already in place).

### [INFO] CORS Dashboard is Same-Origin Only

- **Category:** Cross-Site Resource Sharing
- **Location:** internal/dashboard/middleware.go:108-125
- **Description:** The dashboard CORS middleware sets `Access-Control-Allow-Origin` only on OPTIONS preflight responses (to satisfy browser requirements for custom headers). No `Access-Control-Allow-Origin` is set on actual responses, meaning cross-origin requests are rejected by the browser. This is the correct approach for a same-origin-only application.
- **Remediation:** No action needed.

### [INFO] Content Security Policy Includes form-action Self

- **Category:** Cross-Site Request Forgery
- **Location:** internal/dashboard/middleware.go:69
- **Description:** The CSP header includes `form-action 'self'`, which restricts form submission targets to the same origin. This provides an additional CSRF mitigation layer.
- **Remediation:** No action needed.

---

## Conclusion

**No CSRF vulnerabilities found.** The implementation demonstrates strong CSRF protection through multiple overlapping defenses:

1. **SameSite=Strict cookie** — primary defense, blocks all cross-origin cookie transmission
2. **Same-origin header verification** — defense-in-depth for cookie-authenticated requests
3. **API key header auth** — inherently CSRF-safe, no cookie involved
4. **CSP form-action restriction** — limits form submission targets
5. **No state-changing GET** — all sensitive operations require explicit POST/PUT/DELETE
