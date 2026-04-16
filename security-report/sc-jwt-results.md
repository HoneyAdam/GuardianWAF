# SC: JWT Implementation Flaws — Security Report

**Scanner:** sc-jwt v1.0.0
**Target:** `internal/layers/apisecurity/jwt.go`
**Severity Scale:** Critical | High | Medium | Low

---

## JWT-001: Algorithm "none" Rejection

- **Title:** Algorithm "none" explicitly rejected
- **Severity:** PASS (Secure)
- **Confidence:** 100
- **File:** `internal/layers/apisecurity/jwt.go:217-218`
- **Vulnerability Type:** CWE-347 (Improper Verification of Cryptographic Signature)
- **Description:** The `isAlgorithmAllowed` function explicitly returns `false` for `alg == ""` and `alg == "none"`. Tokens signed with `alg:none` cannot be forged.
- **Impact:** N/A — control is secure.
- **Remediation:** None required.
- **References:** https://cwe.mitre.org/data/definitions/347.html

---

## JWT-002: Algorithm Confusion — HMAC Blocked When Asymmetric Key Source Configured

- **Title:** Algorithm confusion mitigated via asymmetric/HMAC mutual exclusion
- **Severity:** PASS (Secure)
- **Confidence:** 100
- **File:** `internal/layers/apisecurity/jwt.go:220-230`
- **Vulnerability Type:** CWE-347 (Improper Verification of Cryptographic Signature)
- **Description:** If `PublicKeyPEM`, `PublicKeyFile`, or `JWKSURL` is configured (asymmetric sources), the validator blocks HS256/HS384/HS512. This prevents the RS256-to-HS256 algorithm confusion attack where an attacker uses the public RSA key as an HMAC secret.
- **Impact:** N/A — control is secure.
- **Remediation:** None required.
- **References:** https://cwe.mitre.org/data/definitions/347.html

---

## JWT-003: Restrictive Default Algorithm Whitelist

- **Title:** Default algorithm whitelist is restrictive but logged
- **Severity:** Medium
- **Confidence:** 90
- **File:** `internal/layers/apisecurity/jwt.go:232-241`, `internal/layers/apisecurity/jwt.go:109-111`
- **Vulnerability Type:** CWE-345 (Insufficient Verification of Data Authenticity)
- **Description:** When `algorithms` is not configured, the default whitelist is restricted to RS256 and ES256 only. A warning is logged at startup (`log.Println "[jwt] WARNING: JWT validation using default algorithm whitelist..."`). However, this means if no algorithms are explicitly set, the WAF only accepts RS256 and ES256 — other legitimate algorithms like ES512 would be rejected silently without operator awareness.
- **Impact:** Legitimate tokens using non-default algorithms (e.g., ES512, PS256) would be rejected. Operators may not notice the warning during startup.
- **Remediation:** Set the `algorithms` field explicitly in JWT config. Ensure all intended algorithms are listed.
- **References:** https://cwe.mitre.org/data/definitions/345.html

---

## JWT-004: Missing Expiration (exp) Validation

- **Title:** Token expiration is validated
- **Severity:** PASS (Secure)
- **Confidence:** 100
- **File:** `internal/layers/apisecurity/jwt.go:189-192`
- **Vulnerability Type:** CWE-345 (Insufficient Verification of Data Authenticity)
- **Description:** Expiration is validated: `if claims.ExpiresAt > 0 && now > claims.ExpiresAt+skew`. Tokens with `exp == 0` are treated as non-expiring (allowed, since `ExpiresAt > 0` guard).
- **Impact:** N/A — control is secure.
- **Remediation:** None required.
- **References:** https://cwe.mitre.org/data/definitions/345.html

---

## JWT-005: Missing Issuer (iss) Validation

- **Title:** Issuer validation is enforced when configured
- **Severity:** PASS (Secure)
- **Confidence:** 100
- **File:** `internal/layers/apisecurity/jwt.go:199-202`
- **Vulnerability Type:** CWE-345 (Insufficient Verification of Data Authenticity)
- **Description:** Issuer is validated when `v.config.Issuer` is set: `if v.config.Issuer != "" && claims.Issuer != v.config.Issuer`. Returns error on mismatch.
- **Impact:** N/A — control is secure when configured.
- **Remediation:** Ensure `issuer` is set in JWT config.
- **References:** https://cwe.mitre.org/data/definitions/345.html

---

## JWT-006: JWKS Endpoint SSRF Protection

- **Title:** JWKS URL SSRF validation with DNS resolution check
- **Severity:** High (with concern)
- **Confidence:** 85
- **File:** `internal/layers/apisecurity/jwt.go:1071-1112` (`validateJWKSURL`)
- **Vulnerability Type:** CWE-918 (Server-Side Request Forgery)
- **Description:** `validateJWKSURL` rejects localhost, `.internal`, `.local`, `.localhost` hostnames, and private/loopback/link-local IP addresses. It resolves DNS and checks all resulting IPs against private ranges. However:
  - **Gap 1:** DNS resolution results are not restricted to public IP ranges only. An attacker controlling a DNS record (e.g., `jwks.attacker.com` pointing to `10.0.0.1`) could bypass the check if the DNS lookup itself returns a private IP that gets rejected — but the validation logic correctly rejects private IPs. Actually, the logic IS correct here.
  - **Gap 2:** The check uses `net.ParseIP` on resolved addresses, which works for A records but would NOT catch AAAA records (IPv6 addresses). IPv6 private addresses (e.g., `::1`, `fc00::/7`) are not validated.
  - **Gap 3:** The `validateJWKSURL` SSRF check is only called once at initialization (`NewJWTValidator`). If the JWKS URL is changed at runtime, there is no re-validation.
- **Impact:** A malicious JWKS URL pointing to an IPv6 private address could bypass SSRF protection. Runtime config changes to JWKS URL bypass SSRF validation.
- **Remediation:**
  1. Add IPv6 private address validation in `validateJWKSURL`.
  2. Consider re-validating JWKS URL on config reload, or validate it in `fetchJWKS` before making the request.
- **References:** https://cwe.mitre.org/data/definitions/918.html

---

## JWT-007: GenerateToken Test-Only Function Supports Only HS256

- **Title:** Token generation limited to HS256 — low severity in context
- **Severity:** Low
- **Confidence:** 80
- **File:** `internal/layers/apisecurity/jwt.go:1047-1069`
- **Vulnerability Type:** CWE-347 (Improper Verification of Cryptographic Signature)
- **Description:** `GenerateToken` (for testing only) only supports HS256. Combined with the observation that HMAC algorithms are blocked when asymmetric keys are configured, this means GenerateToken tokens cannot be validated by the same validator in asymmetric-key configurations. This is intentional for a test helper but worth noting.
- **Impact:** Test tokens generated with HS256 cannot be validated when JWKS/PEM/keyfile is configured. Low severity because this is a test-only function.
- **Remediation:** Document that `GenerateToken` should only be used for HS256-specific testing.
- **References:** https://cwe.mitre.org/data/definitions/347.html

---

## JWT-008: Ed25519 Support via Raw 32-byte Keys Only

- **Title:** Ed25519 public keys accepted only in raw format (no PKIX wrapper)
- **Severity:** Low
- **Confidence:** 90
- **File:** `internal/layers/apisecurity/jwt.go:1005-1012`
- **Vulnerability Type:** CWE-345 (Insufficient Verification of Data Authenticity)
- **Description:** `parseEd25519PublicKey` only accepts raw 32-byte Ed25519 public keys. Standard PKIX SubjectPublicKeyInfo DER format is explicitly not supported. JWKS keys using `kty: "OKP"` (Octet Key Pair) with `crv: "Ed25519"` would not be parseable via the JWKS path.
- **Impact:** Ed25519 keys from JWKS endpoints in standard format will not be loaded. Operators using Ed25519 via JWKS may get "no verification key available" errors.
- **Remediation:** If Ed25519 JWKS support is needed, extend `parseEd25519PublicKey` to handle PKIX DER format, or ensure JWKS keys are provided in raw format.
- **References:** https://cwe.mitre.org/data/definitions/345.html

---

## JWT-009: No Key ID (kid) Validation Against Injection

- **Title:** kid from JWT header used as map key without sanitization — safe from injection
- **Severity:** PASS (Secure)
- **Confidence:** 90
- **File:** `internal/layers/apisecurity/jwt.go:167-174`
- **Vulnerability Type:** CWE-345 (Insufficient Verification of Data Authenticity)
- **Description:** The `kid` value from the JWT header is used as a key in `sync.Map`. It is not used in any SQL query, filesystem path, or template — only as a map lookup key. No injection risk identified.
- **Impact:** N/A — no injection vector found.
- **Remediation:** None required. Maintain this pattern — do not use `kid` in queries or paths.
- **References:** https://cwe.mitre.org/data/definitions/345.html

---

## Summary

| Finding | Title | Severity | Status |
|---------|-------|----------|--------|
| JWT-001 | Algorithm "none" rejection | PASS | Secure |
| JWT-002 | HMAC blocked with asymmetric keys | PASS | Secure |
| JWT-003 | Default algorithm whitelist restrictive | Medium | Warning |
| JWT-004 | Expiration validation | PASS | Secure |
| JWT-005 | Issuer validation | PASS | Secure |
| JWT-006 | JWKS SSRF protection | High | Gap: IPv6, runtime |
| JWT-007 | GenerateToken HS256 only | Low | Note |
| JWT-008 | Ed25519 raw-key only | Low | Gap |
| JWT-009 | kid injection prevention | PASS | Secure |

**Overall Assessment:** The JWT implementation is well-structured with strong default protections. Algorithm confusion attacks are mitigated, "none" is rejected, signature verification is enforced, and expiration/issuer validation works correctly. The primary concerns are (1) incomplete IPv6 SSRF validation in `validateJWKSURL` and (2) Ed25519 support limited to raw key format, which may affect JWKS-based Ed25519 deployments.
