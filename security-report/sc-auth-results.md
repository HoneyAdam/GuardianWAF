# SC-AUTH: Authentication Flaws Report

**Scanner:** sc-auth v1.0.0
**Target:** GuardianWAF Authentication Mechanisms
**Date:** 2026-04-16
**Severity Classification:** Critical | High | Medium | Low

---

## Summary

| Category | Finding | Severity | Confidence |
|----------|---------|----------|------------|
| Dashboard Auth | AUTH-001: API key in plaintext comparison | Medium | 85 |
| API Key Auth | AUTH-002: SHA256 not adaptive hashing | Medium | 80 |
| Cluster Auth | AUTH-003: Auth secret transmitted in cleartext over HTTP | High | 95 |
| Session Mgmt | AUTH-004: Session token predictability | Low | 70 |
| Rate Limiting | AUTH-005: Login rate limit uses in-memory storage (no cluster distribution) | Medium | 75 |
| JWT Validation | AUTH-006: JWT "none" algorithm rejection not in direct code path | Low | 60 |

---

## Finding: AUTH-001

**Title:** Dashboard login uses constant-time comparison but API key is static
**Severity:** Medium
**Confidence:** 85
**File:** `internal/dashboard/dashboard.go:298-334`
**Vulnerability Type:** CWE-287 (Improper Authentication)
**Description:** The dashboard login (`handleLoginSubmit`) uses `subtle.ConstantTimeCompare` for API key comparison (good), but the API key itself is a static credential with no second factor. The login form is single-factor (API key only). No MFA, no password, no TOTP.
**Impact:** If the static API key is leaked (via logs, config exposure, or source code), attackers can authenticate to the dashboard without any second factor.
**Remediation:**
- Implement time-based one-time passwords (TOTP) as a second factor
- Use short-lived JWT tokens instead of persistent API keys for dashboard sessions
- Rotate the API key automatically after a configurable period

---

## Finding: AUTH-002

**Title:** API key hashing uses SHA256 without salt-based key derivation
**Severity:** Medium
**Confidence:** 80
**File:** `internal/layers/apisecurity/apikey.go:64-77`, `internal/tenant/middleware.go:337`
**Vulnerability Type:** CWE-916 (Weak Password Hash)
**Description:** API keys are stored as SHA256 hashes. The `apikey.go` uses `sha256.Sum256([]byte(apiKey))` which is a fast, non-iterative hash. For API keys used as long-lived credentials, this is a weak storage mechanism compared to adaptive hashing (bcrypt, argon2, scrypt).
**Impact:** If API key hashes are extracted from config, offline brute-force attacks can recover the API keys using GPU-accelerated hashing.
**Remediation:**
- Use bcrypt, argon2, or scrypt for API key hashing with appropriate cost factors
- The dashboard already supports salt$hash format (16-byte hex salt + SHA256), but the apisecurity layer does not

---

## Finding: AUTH-003

**Title:** Cluster authentication secret transmitted in cleartext over HTTP when TLS is not configured
**Severity:** High
**Confidence:** 95
**File:** `internal/cluster/cluster.go:491-492`, `internal/cluster/cluster.go:813-815`
**Vulnerability Type:** CWE-287 (Improper Authentication)
**Description:** The cluster `auth_secret` is sent in the `X-Cluster-Auth` header to other nodes. When TLS is not configured (`TLSCertFile`/`TLSKeyFile` are empty), this header is transmitted in cleartext over HTTP. The code logs a warning when this happens (line 813), but does not enforce TLS.
**Impact:** On a shared network (e.g., internal networks, Kubernetes pods), an attacker who can sniff traffic can intercept the cluster authentication secret and join the cluster as a rogue node.
**Remediation:**
- Require TLS when `AuthSecret` is configured — reject cluster communication over plain HTTP when auth is enabled
- Document that `auth_secret` requires TLS to be effective

---

## Finding: AUTH-004

**Title:** Session token timestamp component is predictable (ts.ts format)
**Severity:** Low
**Confidence:** 70
**File:** `internal/dashboard/auth.go:76-83`
**Vulnerability Type:** CWE-287 (Improper Authentication)
**Description:** Session tokens use format `timestamp.creation_timestamp.signature` where the first two components are identical (`time.Now().Unix()` stored as `ts.created`). While the HMAC signature includes both values, knowing the approximate time of session creation could narrow brute-force search space for session forgery attacks.
**Impact:** If an attacker can predict the approximate session creation time, and the HMAC secret is weak, they could potentially forge session tokens.
**Remediation:**
- Use a cryptographically random session ID separate from timestamps
- Use separate creation timestamp and last-renewal timestamp (already partially implemented via `created` for abs max age tracking)

---

## Finding: AUTH-005

**Title:** Login rate limiting is per-node (in-memory); not distributed across cluster
**Severity:** Medium
**Confidence:** 75
**File:** `internal/dashboard/dashboard.go:94-96`, `internal/dashboard/dashboard.go:336-366`
**Vulnerability Type:** CWE-287 (Improper Authentication)
**Description:** Failed login attempts are tracked in `sync.Map` per node. In a multi-node cluster, an attacker can distribute login attempts across all nodes, each receiving below-threshold attempts. The `loginMaxAttempts=5, loginWindow=5min, loginLockout=15min` per-node limit can be bypassed by spreading attacks.
**Impact:** Brute-force attacks on the dashboard API key can be distributed across cluster nodes, effectively multiplying attempts by the number of nodes.
**Remediation:**
- Share login failure state across cluster nodes (via the cluster's state sync mechanism)
- Use Redis or another distributed store for login attempt tracking
- Consider implementing a cluster-wide IP ban after repeated failures

---

## Finding: AUTH-006

**Title:** JWT "none" algorithm rejection implemented in validator creation but not in direct token validation call path
**Severity:** Low
**Confidence:** 60
**File:** `internal/layers/apisecurity/jwt.go:214-248`
**Vulnerability Type:** CWE-287 (Improper Authentication)
**Description:** The `isAlgorithmAllowed` function rejects "none" at lines 217-219, but it's only called from `Validate()` in the JWT layer. However, the JWT validator has multiple entry points: `Validate()` at line 117 and the internal path via `processToolsCall` in MCP. The direct `Validate()` call path does check algorithm allowlist, but if there were a bypass path (e.g., direct claims parsing without algorithm check), the "none" rejection would not apply.
**Impact:** Low — the primary validation path does reject "none" algorithm.
**Remediation:**
- Add explicit check in the token format validation phase before any parsing

---

## Positive Security Findings

The following strong security practices were observed:

1. **Dashboard session tokens** (`auth.go`):
   - HMAC-SHA256 signed with 32-byte cryptographically random secret
   - IP binding prevents cookie theft across clients
   - Sliding window + absolute maximum lifetime (24h + 7d)
   - Session revocation via `revokedSessions` sync.Map
   - Max concurrent sessions per IP limit (5)

2. **API key storage**:
   - Dashboard supports `salt$hash` format with 16-byte random salt
   - Constant-time comparison via `subtle.ConstantTimeCompare`
   - Rejects API keys in query parameters to prevent log leakage

3. **JWT validation** (`jwt.go`):
   - Algorithm allowlist with explicit rejection of "none"
   - Algorithm confusion prevention: HMAC algorithms rejected when asymmetric key source is configured
   - Claims validation: issuer, audience, exp, nbf
   - JWKS URL SSRF validation with private network blocking
   - Periodic JWKS refresh with panic recovery

4. **Cluster authentication**:
   - Constant-time comparison for auth secret (`subtle.ConstantTimeCompare`)
   - TLS support for encrypted intra-cluster communication
   - Warning log when auth secret is used without TLS

5. **Brute force protection**:
   - Per-IP login rate limiting with lockout (5 attempts / 5 min window / 15 min lockout)
   - CSRF protection via same-origin check on login POST
   - Account enumeration prevention: same error message for invalid key vs rate limit

---

## Recommendations (Priority Order)

| Priority | Recommendation | Finding |
|----------|----------------|---------|
| 1 | Enforce TLS for cluster communication when `AuthSecret` is configured | AUTH-003 |
| 2 | Replace SHA256 with bcrypt/argon2 for API key storage | AUTH-002 |
| 3 | Implement distributed login rate limiting across cluster nodes | AUTH-005 |
| 4 | Add TOTP-based second factor for dashboard login | AUTH-001 |
| 5 | Generate cryptographically random session IDs separate from timestamps | AUTH-004 |

---

## References

- CWE-287: https://cwe.mitre.org/data/definitions/287.html
- CWE-798: https://cwe.mitre.org/data/definitions/798.html
- CWE-916: https://cwe.mitre.org/data/definitions/916.html