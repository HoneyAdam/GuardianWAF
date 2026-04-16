# Business Logic Security Scan Results

**Scanner:** sc-business-logic
**Target:** GuardianWAF - Business Logic Flaws
**Date:** 2026-04-16

---

## Executive Summary

Analyzed multi-tenant isolation, rate limiting, ATO protection, and API security layers for business logic vulnerabilities. Found **5 findings** (1 High, 2 Medium, 2 Low).

---

## Findings

### Finding: BIZ-001

- **Title:** Rate Limit Bucket Exhaustion Bypass
- **Severity:** High
- **Confidence:** 75
- **File:** `internal/layers/ratelimit/ratelimit.go:211-238`
- **Vulnerability Type:** CWE-840 (Business Logic Errors)
- **Description:** When the token bucket map reaches `maxBuckets` (500,000), `getOrCreateBucket()` returns `nil` and the rate limit check is skipped entirely (line 149: `if bucket == nil { continue }`). An attacker could intentionally trigger bucket creation for many IP+tenant combinations to exhaust the limit and bypass rate limiting.
- **Impact:** An attacker with ability to make requests from many IPs (botnet, distributed attack) could bypass all rate limiting by filling the bucket map to capacity. Once full, no new buckets are created and all rate limit rules silently pass for unknown bucket keys.
- **Remediation:** Instead of skipping the rule when bucket creation fails, return `engine.ActionBlock` or fall back to a deny response. Consider implementing a simple per-IP counter that doesn't require bucket allocation.
- **References:** https://cwe.mitre.org/data/definitions/840.html

---

### Finding: BIZ-002

- **Title:** Tenant Rate Limiter Counter Reset on Auto-Ban Expiry
- **Severity:** Medium
- **Confidence:** 70
- **File:** `internal/layers/ratelimit/ratelimit.go:274-293`
- **Vulnerability Type:** CWE-840 (Business Logic Errors)
- **Description:** When auto-ban triggers after `rule.AutoBanAfter` violations, the violation counter is reset to 0 (line 291). The ban has a fixed duration (`BlockDuration`). After the ban expires, the attacker has a "clean slate" and can immediately begin accumulating violations again without any historical context. An attacker could cycle through this: make banned-1 requests, get banned briefly, wait out the ban, repeat.
- **Impact:** Persistent attacker can maintain a low-and-slow brute force or abuse campaign indefinitely by keeping requests just below the auto-ban threshold and cycling bans.
- **Remediation:** Consider using a sliding window for violation counting that doesn't reset completely on ban. Alternatively, use a longer-term counter (e.g., 24-hour rolling window) for ban decisions that decays but doesn't hard-reset.
- **References:** https://cwe.mitre.org/data/definitions/840.html

---

### Finding: BIZ-003

- **Title:** Impossible Travel Detection Bypass via Small Distances
- **Severity:** Medium
- **Confidence:** 65
- **File:** `internal/layers/ato/ato.go:262-306`
- **Vulnerability Type:** CWE-840 (Business Logic Errors)
- **Description:** The impossible travel check requires BOTH `speed > 1000 km/h` AND `distance > cfg.MaxDistanceKm` (line 298). If `MaxDistanceKm` is set to a high value (e.g., default or misconfigured), an attacker making rapid logins from geographically close but "impossible" locations (e.g., different cities 200km apart in 10 minutes = 1200 km/h) could bypass detection if MaxDistanceKm > 200. The speed check alone (1000 km/h) could be achieved with short flights between nearby cities.
- **Impact:** A sophisticated attacker could exploit impossible travel detection gaps by making rapid login attempts from multiple nearby locations, potentially bypassing fraud detection.
- **Remediation:** Consider making the two conditions independent (either speed OR distance violation triggers alert). Or require BOTH conditions with lower thresholds.
- **References:** https://cwe.mitre.org/data/definitions/840.html

---

### Finding: BIZ-004

- **Title:** ATO Brute Force Per-Email Counter Incomplete for Credential Stuffing
- **Severity:** Low
- **Confidence:** 60
- **File:** `internal/layers/ato/ato.go:212-232`
- **Vulnerability Type:** CWE-840 (Business Logic Errors)
- **Description:** The brute force check per-email tracks `GetEmailAttempts()` which counts all attempts for a given email within a window. However, this doesn't account for distributed attacks where the same email is attacked from many IPs (already caught by credential stuffing detection at line 234-245). The concern is that legitimate failed attempts from different IPs (user typo, password expiry) could combine with an attacker's attempts to trigger a false positive block.
- **Impact:** Legitimate users may be blocked after repeated password mistakes across different IPs, especially in corporate environments with multiple exit IPs.
- **Remediation:** Consider requiring attempts from multiple IPs before blocking an email for brute force (similar to credential stuffing logic). The current implementation correctly separates brute force (per-email count) from credential stuffing (unique IP count), but the interaction could be refined.
- **References:** https://cwe.mitre.org/data/definitions/840.html

---

### Finding: BIZ-005

- **Title:** Tenant Resolution Order Allows Header-Based Tenant Impersonation
- **Severity:** Low
- **Confidence:** 55
- **File:** `internal/tenant/middleware.go:335-359`
- **Vulnerability Type:** CWE-840 (Business Logic Errors)
- **Description:** `ResolveTenant()` checks `X-GuardianWAF-Tenant-Key` header first (line 337), before domain-based resolution. While this is intentional for API access, it means a compromised or leaked API key could be used to impersonate any tenant by setting this header. The domain-based routing (line 344-350) is bypassed entirely when the header is present.
- **Impact:** If an API key is compromised, the attacker can access any tenant's resources regardless of the request's Host header. This is mitigated if API keys are properly secured and rotated.
- **Remediation:** Consider adding validation that the API key matches the requested tenant, or requiring multi-factor confirmation for cross-tenant API access. Log all API key-based tenant resolutions for audit.
- **References:** https://cwe.mitre.org/data/definitions/840.html

---

## Secure Patterns Observed

The codebase demonstrates several secure business logic patterns:

1. **Tenant isolation via bucket keys** (`ratelimit.go:192-207`): Rate limit buckets include tenant ID, preventing cross-tenant bypass.

2. **JWT tenant binding validation** (`apisecurity.go:115-132`): JWT tokens with mismatched `tenant_id` claim are rejected, preventing cross-tenant token reuse.

3. **API key constant-time comparison** (`apikey.go:114-118`): Uses `subtle.ConstantTimeCompare` for hash comparison to prevent timing attacks.

4. **HMAC algorithm blocking** (`jwt.go:220-230`): Prevents algorithm confusion attacks by blocking HMAC when asymmetric keys are configured.

5. **JWKS SSRF protection** (`jwt.go:1071-1112`): Validates JWKS URLs don't target private networks.

6. **Billing overage guards** (`billing.go:187-199`): Request and bandwidth overage only charged when positive.

7. **Rate tracker map size limits** (`ratetracker.go:78-83`): Prevents memory exhaustion via entry limits.

---

## Recommendations

1. **BIZ-001 (High)**: Add a fallback rate limit response when bucket creation fails. Consider implementing a "global rate limit" that applies to all requests when buckets are exhausted.

2. **BIZ-002 (Medium)**: Implement violation count persistence that survives ban expiry. Consider a decay function rather than hard reset.

3. **BIZ-003 (Medium)**: Review `MaxDistanceKm` configuration defaults. Consider lowering the speed threshold or making distance/speed checks independent.

4. **BIZ-004 (Low)**: Consider adding source IP diversity requirements to brute force detection.

5. **BIZ-005 (Low)**: Ensure API keys are regularly rotated and implement logging/monitoring for tenant resolution via API key.
