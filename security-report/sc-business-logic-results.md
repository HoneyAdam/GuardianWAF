# Business Logic Flaws Scan - GuardianWAF

## Scanner: sc-business-logic
## Target: Pure Go WAF codebase (GuardianWAF)
## Date: 2026-04-15

---

## Executive Summary

One business logic flaw was identified (medium severity): the WAF exclusion bypass via path traversal sequences in the pipeline layer. All seven security categories were analyzed, and the other six did not yield findings.

---

## Findings

### [MEDIUM] WAF Exclusion Bypass via Path Traversal Sequences

- **Category:** Business Logic Flaw
- **Location:** internal/engine/pipeline.go:96
- **Description:** The `shouldSkip` function uses `strings.HasPrefix(path, exc.PathPrefix)` to check if a request path matches an exclusion rule. However, the exclusion matching does not canonicalize the request path first. An attacker can bypass exclusion rules by inserting path traversal sequences (e.g., `/api/webhook/../../etc/passwd` or `/api/webhook/./`) that modify the effective path while still reaching the same resource.

  The pipeline does normalize the path via `ctx.NormalizedPath` (set by the Sanitizer layer at Order 300), but the exclusion check at line 96 falls back to `ctx.Path` (the raw, unnormalized path) when `NormalizedPath` is empty. This means:

  1. Requests reaching the pipeline before the Sanitizer layer (Order < 300) use raw path for exclusion matching
  2. A request to `/api/webhook/../../admin` with an exclusion for `/api/webhook` will NOT match the exclusion when the sanitizer has normalized the path to `/admin`, but the bypass works the opposite direction: raw path with `../` can escape the prefix check even though the actual resource being accessed is normalized

  The vulnerability manifests because exclusion rules are evaluated against the raw `ctx.Path` before path canonicalization, allowing attacks like `/api/webhook/..%2F..%2F/etc/passwd` (URL-encoded or raw) to bypass exclusions.

  Note: The sanitization layer (Order 300) runs before the detection layer (Order 400), so by the time detection exclusions are checked, `ctx.NormalizedPath` should be populated. However, the fallback to raw path exists for early-stage layers and the logic is not consistently applied.

- **Remediation:** Canonicalize the path before exclusion matching in `shouldSkip`. Use the same `path.Clean` logic that the sanitizer uses, or require that exclusion paths be normalized before being stored in the pipeline. The fix should ensure that `/api/webhook/../../admin` and `/admin` both match an exclusion for `/admin`.

---

## Analysis Details by Category

### 1. Integer Overflow in Security Values

**Status:** No issues found

Key observations:
- `RequestCount`, `ByteCount`, and `BlockedCount` in the `Tenant` struct (internal/tenant/manager.go:43-46) are `int64`, which provides a very large upper bound (9.2e18)
- `ScoreAccumulator` uses `int` for scores but detectors cap individual scores at 100, and the accumulator tracks total score across all layers — with 16 layers, max score is 1600, well within int range
- Rate limit counters in `ratelimit.go:38` use `*atomic.Int64` for violation tracking
- Bucket count in rate limiter is capped at 500,000 (line 45: `maxBuckets = 500000`) to prevent memory exhaustion, not overflow
- The code uses Go 1.21+ idioms like `min()` and `slices.Contains` throughout

**Positive patterns observed:**
- All counters that could be attacker-influenced use atomic operations or mutex protection
- No arithmetic operations on security-critical values that could overflow
- Hard limits are enforced (bucket cap, header count limits, body size limits)

---

### 2. Race Conditions in Security Checks

**Status:** No issues found

Key observations:
- Tenant resolution in `middleware.go:37-88` is atomic: the tenant is resolved once at the start of request processing and stored in the request context
- `TenantWAFConfig` is read directly by each layer via `ctx.TenantWAFConfig`, which is set once per request and never modified during pipeline execution
- `RequestContext` is pooled via `sync.Pool` (context.go:132-136), but fields are properly reset in `ReleaseContext()` (line 247-293)
- The `Pipeline` uses `sync.RWMutex` for layer list and exclusion updates (pipeline.go:35-37)
- `TenantRateLimiter` uses proper locking for all operations (ratetracker.go:67-150)
- `TokenBucket` uses `sync.Mutex` for all operations (bucket.go:10-66)
- `IP ACL Layer` uses `sync.RWMutex` for auto-ban map protection (ipacl.go:39)

---

### 3. Bypass via Method Switching

**Status:** No issues found

Key observations:
- The sanitizer layer (`validate.go:115-135`) validates HTTP method against `AllowedMethods` config using case-insensitive comparison
- The detection layer runs the same detectors regardless of HTTP method — there is no method-based skip logic
- Pipeline execution order does not change based on method — all layers run in order
- No difference in enforcement between GET/POST/HEAD requests
- The `Method` field in `RequestContext` is populated directly from `r.Method` and not modified during processing

---

### 4. Multi-Tenancy Bypass

**Status:** No issues found

Key observations:
- Tenant resolution uses multiple factors: API key header (`X-GuardianWAF-Tenant-Key`), domain-based routing, and default tenant fallback (manager.go:335-359)
- API keys are hashed with per-tenant random salt using SHA256 (manager.go:724-733), with legacy unsalted hash support for backwards compatibility
- Tenant config (`TenantWAFConfig`) is isolated per-request via `RequestContext` — layers read tenant overrides directly from `ctx.TenantWAFConfig` without any cross-tenant reference
- Tenant rules are stored in isolated `rules.Layer` instances keyed by tenant ID (rules.go:14-64)
- Tenant rate tracking uses isolated `RateTracker` instances per tenant (ratetracker.go:67-150)
- The `Middleware.Handler` sets tenant context before calling the next handler (middleware.go:58-76)
- No evidence of tenant ID confusion or cross-tenant data access in the codebase
- `safeTenantID` validation (store.go:23-38) ensures tenant IDs contain only safe characters

---

### 5. Quota Bypass

**Status:** No issues found

Key observations:
- Rate limiting in `ratelimit.go` uses token bucket algorithm with proper mutex protection
- Bucket keys include normalized IP (`bucketKey` function, lines 189-205) to prevent bypass via IPv4-mapped IPv6 addresses
- Path normalization uses `path.Clean` for `ip+path` scope rules to prevent path-based bypass
- Hard cap on total buckets (500,000) prevents memory exhaustion attacks
- Violation counter for auto-ban uses atomic operations (`atomic.Int64`) with proper threshold checking (ratelimit.go:274-290)
- Tenant quotas use sliding window algorithm (`RateTracker` in ratetracker.go:9-65) with proper mutex locking
- No evidence of race conditions in quota checking — all quota checks use `mu.Lock()` or `mu.RLock()` appropriately

---

### 6. Authentication Bypass via Race

**Status:** No issues found

Key observations:
- JWT validation (`jwt.go:116-211`) performs all checks (algorithm, signature, claims expiry, issuer, audience) atomically within a single `Validate` function call — no time-of-check-time-of-use (TOCTOU) issues
- API key validation follows a similar pattern: extract key, validate, return result — no multiple steps that could race
- `JWTValidator.isAlgorithmAllowed` (lines 213-241) correctly prevents algorithm confusion attacks by blocking HMAC when an asymmetric key source is configured
- JWKS fetching uses proper timeout and context cancellation (lines 370-450)
- SSRF protection exists for JWKS URL validation (`validateJWKSURL` function, lines 1066-1106) — validates against localhost, private, and link-local addresses
- No authentication bypass via concurrent requests detected

---

### 7. Exclusion Bypass (DETAILED ABOVE)

**Finding ID:** BL-001
**Severity:** MEDIUM

See the dedicated finding above for the complete description and remediation.

---

## Conclusion

The GuardianWAF codebase demonstrates strong security design patterns. Business logic flaws are minimal — the codebase uses proper locking, atomic operations, and isolated contexts throughout. One medium-severity finding was identified: the exclusion bypass via path traversal sequences, which could allow an attacker to circumvent WAF exclusion rules through crafted paths containing `..` sequences.

All other categories (integer overflow, race conditions, method switching, multi-tenancy, quota bypass, authentication race) passed analysis with no findings.

---

## Files Analyzed

- internal/engine/pipeline.go
- internal/engine/context.go
- internal/engine/layer.go
- internal/tenant/manager.go
- internal/tenant/middleware.go
- internal/tenant/ratetracker.go
- internal/tenant/rules.go
- internal/tenant/store.go
- internal/layers/ratelimit/ratelimit.go
- internal/layers/ratelimit/bucket.go
- internal/layers/ipacl/ipacl.go
- internal/layers/sanitizer/sanitizer.go
- internal/layers/sanitizer/normalize.go
- internal/layers/sanitizer/validate.go
- internal/layers/detection/detection.go
- internal/layers/apisecurity/apisecurity.go
- internal/layers/apisecurity/jwt.go