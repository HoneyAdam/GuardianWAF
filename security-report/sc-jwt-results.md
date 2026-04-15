# JWT Security Scan Results

**Scanner:** sc-jwt (JWT Implementation Scanner)
**Target:** `internal/layers/apisecurity/jwt.go`
**Date:** 2026-04-15

---

## Summary

| Check | Status | Risk |
|-------|--------|------|
| Algorithm Allowlist | PASS | Low |
| Algorithm Confusion Protection | PASS | Low |
| Claims Validation (exp, aud, iss, nbf) | PASS | Low |
| kid Parameter Safety | PASS | Low |
| JWKS URL SSRF Validation | PASS | Low |
| "none" Algorithm Blocking | PARTIAL | Medium |
| Weak Secret Validation | FAIL | Medium |

---

## Findings

### [LOW] Default Algorithm Restriction with Warning

- **Category:** JWT Implementation
- **Location:** `jwt.go:106-110, 226-234`
- **Description:** When no `algorithms` array is configured, the validator defaults to RS256 and ES256 only, which is secure. However, a warning is logged instead of failing hard. Misconfigured deployments could inadvertently allow additional algorithms if `algorithms` is later set to an empty array in config.
- **Remediation:** Consider failing validation at startup if no explicit `algorithms` list is provided in production environments, rather than warning and accepting defaults.

---

### [MEDIUM] "none" Algorithm Not Explicitly Blocked

- **Category:** JWT Implementation Flaws
- **Location:** `jwt.go:213-241`
- **Description:** The `isAlgorithmAllowed` function does not explicitly block the "none" algorithm. While the default algorithm list (RS256, ES256) excludes "none", and the signature verification step requires a non-nil key, explicit blocking is recommended per OWASP guidelines. If a user mistakenly adds "none" to their `algorithms` config, it would be accepted.
- **Remediation:** Add explicit rejection of "none" algorithm in `isAlgorithmAllowed`:
  ```go
  if alg == "none" || alg == "" {
      return false
  }
  ```

---

### [MEDIUM] No Weak Secret Validation for HMAC Keys

- **Category:** Weak Cryptographic Secrets
- **Location:** `jwt.go:213-224, 354-368`
- **Description:** When HMAC algorithms (HS256, HS384, HS512) are legitimately used with symmetric keys, there is no validation of secret key strength. Weak keys (e.g., "secret", "password", "123456") would be accepted. The implementation correctly blocks HMAC when asymmetric key sources are configured (preventing algorithm confusion), but when HMAC is intentionally used, key strength is not checked.
- **Remediation:** Add minimum key length validation for HMAC secrets (minimum 256 bits / 32 bytes for HS256). Reject keys below this threshold with a clear error message.

---

## Positive Security Controls

The implementation includes several strong security measures:

1. **Algorithm Confusion Prevention (jwt.go:213-224):** When asymmetric key sources are configured (PEM, key file, or JWKS URL), HMAC algorithms are explicitly rejected. This prevents the classic RS256-to-HS256 algorithm confusion attack.

2. **Complete Claims Validation (jwt.go:184-208):** All standard claims are validated:
   - `exp` (Expiration) with configurable clock skew
   - `nbf` (Not Before) with configurable clock skew
   - `iss` (Issuer) with exact match
   - `aud` (Audience) with support for string, []any, and []string types

3. **kid Safety (jwt.go:166-173):** The `kid` parameter is used only as a sync.Map key for JWKS cache lookup. No file path, SQL, or other injection vectors.

4. **JWKS URL SSRF Protection (jwt.go:1065-1106):** The `validateJWKSURL` function blocks:
   - Localhost and .internal/.local/.localhost domains
   - IPv4 loopback (127.0.0.0/8)
   - IPv4 private ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
   - IPv6 loopback, private, link-local, and unspecified addresses
   - DNS resolution with IP validation of all returned addresses

5. **Response Size Limiting (jwt.go:406):** JWKS response is limited to 1MB via `io.LimitReader`.

---

## Recommendations

1. Explicitly block "none" algorithm in `isAlgorithmAllowed`
2. Add minimum key length validation for HMAC secrets (32 bytes for HS256)
3. Consider failing at startup if no explicit algorithms list is configured
4. Add IPV6 CIDR validation in `validateJWKSURL` (currently only checks specific IPv6 address types, not CIDR ranges)
