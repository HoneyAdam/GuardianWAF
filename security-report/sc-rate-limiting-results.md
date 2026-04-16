# SC-RATE-LIMITING: Rate Limiting Security Assessment

## Summary

| Category | Status |
|----------|--------|
| Token Bucket Implementation | SECURE with minor issues |
| IP Spoofing Protection | SECURE |
| Auto-ban Mechanism | SECURE |
| Memory Exhaustion Protection | SECURE with bug |
| Sensitive Endpoint Coverage | NEEDS HARDENING |
| Race Condition Handling | ACCEPTABLE |

---

## Findings

### RATE-001: Missing Auth-Endpoint-Specific Rate Limits

- **Title:** Missing Rate Limiting on Authentication Endpoints
- **Severity:** High
- **Confidence:** 90
- **File:** `internal/config/defaults.go:34-43`
- **Vulnerability Type:** CWE-799 (Improper Control of Interaction Frequency)
- **Description:** Default rate limit is a single global rule (1000 req/min, 50 burst) that applies to all endpoints uniformly. No special rate limiting is configured for sensitive auth endpoints (`/login`, `/password/reset`, `/otp`, `/register`).
- **Impact:** Brute force attacks against authentication endpoints are only mitigated by the ATO Protection layer, not by explicit rate limiting. If ATO is disabled or misconfigured, auth endpoints are vulnerable.
- **Remediation:** Add specific rate limit rules with stricter limits for auth endpoints:
  ```yaml
  rate_limit:
    rules:
      - id: auth-strict
        scope: ip
        paths: ["/login", "/password/reset", "/register"]
        limit: 5
        window: 1m
        burst: 5
        action: block
  ```
- **References:** https://cwe.mitre.org/data/definitions/799.html

---

### RATE-002: Violations Counter Never Cleaned Up

- **Title:** Violation Counters Can Grow Unbounded
- **Severity:** Medium
- **Confidence:** 85
- **File:** `internal/layers/ratelimit/ratelimit.go:276-293`
- **Vulnerability Type:** CWE-770 (Allocation Without Limits)
- **Description:** The `violations` sync.Map stores violation counters for auto-ban tracking but has no cleanup mechanism and no hard cap. Unlike `buckets` which have `maxBuckets = 500000` and `CleanupExpired()`, the violations map can grow indefinitely.
- **Impact:** Under sustained attack from many unique IPs, the violations map consumes increasing memory without bound. Each violation entry is small but can accumulate over time.
- **Remediation:** Add a `CleanupViolations()` method similar to `CleanupExpired()` for buckets, or incorporate violation cleanup into the existing `CleanupExpired()` call. Add a max violations entries cap.
- **References:** https://cwe.mitre.org/data/definitions/770.html

---

### RATE-003: CleanupExpired Does Not Decrement bucketCount

- **Title:** Bucket Counter Drift After Cleanup
- **Severity:** Low
- **Confidence:** 75
- **File:** `internal/layers/ratelimit/ratelimit.go:296-322`
- **Vulnerability Type:** CWE-400 (Uncontrolled Resource Consumption)
- **Description:** `CleanupExpired()` deletes stale buckets from `buckets` sync.Map but does NOT decrement `bucketCount`. This causes `bucketCount` to drift upward over time, potentially reaching `maxBuckets` prematurely and causing legitimate new buckets to be rejected.
- **Impact:** Under low-traffic scenarios where buckets expire via cleanup, the bucket counter will eventually reach the 500,000 limit even though fewer buckets actually exist. This would cause rate limiting to stop creating new buckets for new IP/path combinations.
- **Remediation:** Add `l.bucketCount.Add(-1)` when deleting a bucket in `CleanupExpired()`:
  ```go
  if bucket.LastAccess().Before(cutoff) {
      l.buckets.Delete(key)
      l.bucketCount.Add(-1) // Add this line
  }
  ```
- **References:** https://cwe.mitre.org/data/definitions/400.html

---

### RATE-004: Race Condition Window in getOrCreateBucket

- **Title:** Potential bucketCount Exceedance Under High Concurrency
- **Severity:** Low
- **Confidence:** 60
- **File:** `internal/layers/ratelimit/ratelimit.go:211-238`
- **Vulnerability Type:** CWE-362 (Use of a Shared Resource in a Concurrency-Sensitive Manner)
- **Description:** Between checking `l.bucketCount.Load() >= maxBuckets` and calling `l.buckets.LoadOrStore()`, another goroutine could create a bucket. The check is not atomic with the store. Under extreme concurrency, `bucketCount` could briefly exceed `maxBuckets` by the number of concurrent goroutines that pass the check before any stores.
- **Impact:** Minor transient exceedance of bucket cap. The hard limit is violated only briefly and recovers automatically since `bucketCount.Add(1)` only happens on actually new buckets.
- **Remediation:** Acceptable as-is given the sync.Map's atomic LoadOrStore, or use a mutex-protected check+insert pattern with deferred count adjustment.
- **References:** https://cwe.mitre.org/data/definitions/362.html

---

### RATE-005: No User-Based Rate Limiting

- **Title:** Rate Limiting Only Supports IP Scope
- **Severity:** Medium
- **Confidence:** 80
- **File:** `internal/layers/ratelimit/ratelimit.go:16-25`
- **Vulnerability Type:** CWE-799 (Improper Control of Interaction Frequency)
- **Description:** Rate limit rules only support `ip` and `ip+path` scopes. After a user authenticates, there is no mechanism to rate limit per-user (e.g., per account ID or session). An attacker with multiple IPs could still overwhelm a specific user account.
- **Impact:** Credential stuffing and brute force attacks against specific user accounts are harder to detect without user-level rate limiting.
- **Remediation:** Consider adding a `user` or `session` scope option that uses `ctx.SessionID` or `ctx.UserID` (if available in RequestContext) as the bucket key. The ATO layer partially mitigates this via per-email tracking.
- **References:** https://cwe.mitre.org/data/definitions/799.html

---

## Positive Findings

### IP Spoofing Protection (SECURE)

The rate limiting layer correctly uses `extractClientIP()` which:
- Walks X-Forwarded-For from RIGHT to left (not leftmost, which is attacker-controlled)
- Only trusts proxy headers when the direct connection is from a trusted proxy
- Properly handles IPv4-mapped IPv6 addresses to prevent dual-stack bypass

**File:** `internal/engine/context.go:311-343`

### Token Bucket Atomicity (SECURE)

The `Allow()` method correctly holds the mutex for both refill calculation AND token decrement, preventing any race between threads checking and consuming tokens.

**File:** `internal/layers/ratelimit/bucket.go:31-43`

### Memory Cap on Buckets (SECURE)

Hard cap of 500,000 buckets prevents memory exhaustion from bucket accumulation.

**File:** `internal/layers/ratelimit/ratelimit.go:45`

### Multi-Tenant Isolation (SECURE)

Bucket keys include `tenantID`, providing proper per-tenant rate limit isolation.

**File:** `internal/layers/ratelimit/ratelimit.go:192-208`

### Auto-Ban Mechanism (SECURE)

Violation tracking uses atomic operations and resets counter after ban to allow future cycles.

**File:** `internal/layers/ratelimit/ratelimit.go:274-293`

---

## Recommendations (Priority Order)

1. **HIGH:** Add auth endpoint-specific rate limit rules to defaults
2. **MEDIUM:** Add cleanup mechanism for violation counters
3. **LOW:** Fix `CleanupExpired()` to decrement `bucketCount`
4. **LOW:** Consider adding user/session-based scope option
