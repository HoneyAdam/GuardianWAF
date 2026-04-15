# sc-auth Results: GuardianWAF Authentication Security Scan

**Target:** Go WAF with dashboard and API
**Date:** 2026-04-15
**Scanner:** sc-auth (security-check skill)

---

## Summary

No authentication flaws found.

---

## Detailed Findings

### [PASS] Password Hashing

- **Category:** Authentication - Password Storage
- **Location:** N/A (not applicable)
- **Description:** GuardianWAF does not use passwords for primary authentication. The dashboard uses API key authentication (HMAC-signed session tokens). API keys are stored as SHA256 hashes in configuration. No password hashing mechanism (bcrypt/argon2) is used because passwords are not the auth method.
- **Remediation:** N/A

### [PASS] Brute Force Protection

- **Category:** Authentication - Brute Force Protection
- **Location:** `internal/dashboard/dashboard.go:91-108`, `internal/dashboard/auth.go`
- **Description:** Dashboard login implements per-IP rate limiting with lockout:
  - `loginMaxAttempts = 5` (max failed attempts before lockout)
  - `loginWindow = 5 * time.Minute` (sliding window)
  - `loginLockout = 15 * time.Minute` (lockout duration)
  - `checkLoginRateLimit()` and `recordLoginFailure()` implemented
  - Cleanup goroutine `cleanupLoginBuckets()` prevents memory bloat
- **Remediation:** N/A

### [PASS] No Hardcoded Credentials

- **Category:** Authentication - Hardcoded Secrets
- **Location:** `cmd/guardianwaf/main.go:685-711`
- **Description:** Dashboard password is generated dynamically via `generateDashboardPassword()` using `cryptoRand.Read()` (CSPRNG). Fallback uses `sha256.Sum256()` with process-specific entropy (PID, memstats, nanoseconds). No hardcoded admin passwords exist in code. Default credentials are not present.
- **Remediation:** N/A

### [PASS] Timing-Safe Comparison

- **Category:** Authentication - Timing Attack Prevention
- **Location:** `internal/dashboard/auth.go:130`, `internal/layers/apisecurity/apikey.go:115`
- **Description:** API key comparison uses `subtle.ConstantTimeCompare()`:
  - `auth.go:130`: `subtle.ConstantTimeCompare([]byte(key), []byte(d.apiKey)) == 1`
  - `apikey.go:115`: `subtle.ConstantTimeCompare([]byte(h), []byte(hashStr)) == 1`
  - HMAC signature verification uses `hmac.Equal()` (timing-safe)
- **Remediation:** N/A

### [PASS] Session Management

- **Category:** Authentication - Session Security
- **Location:** `internal/dashboard/auth.go:148-158`
- **Description:** Session cookie configured with strong security flags:
  - `HttpOnly: true` (prevents JavaScript access)
  - `Secure: true` (TLS required)
  - `SameSite: http.SameSiteStrictMode` (CSRF protection)
  - `MaxAge: int(sessionMaxAge.Seconds())` (24-hour sliding expiry)
  - Session signed with HMAC-SHA256 bound to client IP
  - Absolute session lifetime: 7 days (`sessionAbsMaxAge`)
- **Remediation:** N/A

### [PASS] API Key Storage

- **Category:** Authentication - API Key Security
- **Location:** `internal/layers/apisecurity/apikey.go:15`, `internal/dashboard/auth.go:122-127`
- **Description:** API keys stored as `sha256:hex` or `bcrypt:hash` (per `KeyHash` field in `APIKeyConfig`). The dashboard API key is stored in config as a raw value but compared using `subtle.ConstantTimeCompare()`. API keys in query parameters are explicitly rejected to prevent log leakage (`auth.go:133-137`).
- **Remediation:** N/A

### [PASS] Authentication Bypass

- **Category:** Authentication - Access Control
- **Location:** `internal/dashboard/dashboard.go:124-179`
- **Description:** All sensitive dashboard endpoints are wrapped with `authWrap()` middleware. Publicly accessible endpoints are limited to:
  - `GET /login` - login page
  - `POST /login` - login submission (rate-limited)
  - `GET /logout` - logout
  - `GET /api/v1/health` - health check (no sensitive data)
  - `OPTIONS /api/v1/config` and `OPTIONS /api/v1/routing` - CORS preflight
  - All other endpoints require authentication via session cookie or `X-API-Key` header.
- **Remediation:** N/A

---

## Additional Security Notes (Informational)

1. **JWT Validation** (`internal/layers/apisecurity/jwt.go`): Robust implementation with algorithm restriction, issuer/audience validation, clock skew handling, SSRF protection on JWKS URL, and asymmetric key confusion prevention.

2. **No Password Auth for Dashboard**: The dashboard uses API key authentication, not username/password. This avoids password hashing concerns entirely.

3. **Setup Wizard** (`cmd/guardianwaf/main.go:174-175`): Auto-generates a cryptographically secure password during first-time setup.

4. **Zero-Trust Architecture**: ATO protection layer (Order 250) includes brute force detection, credential stuffing detection, password spray detection, and impossible travel detection.
