# Rate Limiting & DoS Security Scan Results

**Scanner:** sc-rate-limiting
**Target:** Pure Go WAF codebase (GuardianWAF)
**Date:** 2026-04-15

---

## Summary

| Check | Status | Notes |
|-------|--------|-------|
| Rate limiting implementation | PASS | Token bucket algorithm with auto-ban |
| Bypass vectors | PASS | IP normalization, path cleaning, proxy header handling |
| Per-tenant limits | FAIL | Rate limit buckets lack tenant isolation |
| Global vs per-path | PASS | Supports both "ip" and "ip+path" scopes |
| Slowloris protection | PASS | ReadTimeout 30s, ReadHeaderTimeout 10s |
| Header exhaustion | PASS | Max 100 headers enforced in context.go:167-175 |
| Body size limits | PASS | maxBodySize via io.LimitReader in context.go:193 |
| Connection limits | PASS | MaxConnsPerHost: 100 at proxy transport level |

---

## Findings

### [HIGH] Per-tenant rate limit buckets are not isolated by tenant

- **Category:** Rate Limiting / Multi-Tenancy
- **Location:** `internal/layers/ratelimit/ratelimit.go:189-205`
- **Description:** The `bucketKey` function generates keys using only `rule.ID`, IP, and path. Tenant ID is not included in the bucket key. This means all tenants share the same rate limit buckets for a given IP address — one tenant's traffic can exhaust another tenant's rate limit.
- **Evidence:**
  ```go
  switch rule.Scope {
  case "ip+path":
      normalized := path.Clean(reqPath)
      return rule.ID + ":" + normalizedIP + ":" + normalized
  default: // "ip" or anything else
      return rule.ID + ":" + normalizedIP
  }
  ```
  `ctx.TenantID` is available but not used in the bucket key.
- **Remediation:** Include tenant ID in the bucket key when `ctx.TenantID` is non-empty:
  ```go
  return rule.ID + ":" + tenantID + ":" + normalizedIP + ":" + normalized
  ```

---

### [INFO] Auto-ban trigger counter is not tenant-isolated

- **Category:** Rate Limiting / Multi-Tenancy
- **Location:** `internal/layers/ratelimit/ratelimit.go:272-290`
- **Description:** The `trackViolation` function uses key `"violation:" + rule.ID + ":" + ip` without tenant isolation. Violation counts for auto-ban are shared across tenants for the same IP/rule combination.
- **Remediation:** Include tenant ID in the violation tracking key when multi-tenant isolation is required.

---

## All Checks Detailed

### 1. Rate Limiting Implementation — PASS

Rate limiting is implemented in `internal/layers/ratelimit/ratelimit.go` using a token bucket algorithm (`bucket.go`). The layer integrates into the WAF pipeline at Order 200 and supports:
- Configurable rules with "ip" or "ip+path" scope
- Burst capacity via `Rule.Burst`
- Auto-ban after N violations (`Rule.AutoBanAfter`)
- Hard cap of 500,000 buckets to prevent memory exhaustion (`maxBuckets`)
- Periodic cleanup of stale buckets via `Cleanup()` / `CleanupExpired()`

### 2. Bypass Vectors — PASS

The implementation includes protections against common bypass techniques:
- **IPv6 dual-stack bypass:** `bucketKey` normalizes IPv4-mapped IPv6 addresses (::ffff:x.x.x.x) to their IPv4 representation (`ratelimit.go:193-196`)
- **Path traversal bypass:** Uses `path.Clean(reqPath)` to resolve ".." sequences (`ratelimit.go:201`)
- **Proxy header spoofing:** When no trusted proxies are configured, `X-Forwarded-For` and `X-Real-IP` are ignored; when trusted proxies are configured, the rightmost non-trusted IP is used (not the leftmost) (`context.go:311-346`)
- **Excessive headers:** Stops processing at 100 headers to prevent header exhaustion DoS (`context.go:167-175`)

### 3. Per-Tenant Limits — FAIL

Tenant configuration can disable rate limiting (`ctx.TenantWAFConfig.RateLimit.Enabled`), but when enabled, all tenants share the same global rate limit buckets. The bucket key does not include `ctx.TenantID`, so per-IP rate limits aggregate traffic across tenants.

### 4. Global vs Per-Path — PASS

Rate limiting rules support both global ("ip" scope) and per-path ("ip+path" scope) limiting. Path matching uses glob patterns with support for `**` suffix to match all paths under a prefix (`ratelimit.go:238-270`).

### 5. Slowloris Protection — PASS

All HTTP servers are configured with:
- `ReadTimeout: 30 * time.Second` — protects against slow client body transmission
- `ReadHeaderTimeout: 10 * time.Second` — specifically mitigates slowloris attacks on header reading
- TLS servers have equivalent timeouts (`main_default.go:973-976`, `main_default.go:1014-1017`)

### 6. Header Exhaustion — PASS

`context.go:167-175` caps header processing at 100 headers:
```go
ctx.Headers = make(map[string][]string, min(len(r.Header), 100))
for k, v := range r.Header {
    if len(ctx.Headers) >= 100 {
        break // Excessive headers — stop processing to prevent resource exhaustion
    }
    ...
}
```
HTTP/3 servers additionally support configurable `MaxHeaderBytes` (default 1MB) via `cfg.TLS.HTTP3.MaxHeaderBytes`.

### 7. Body Size Limits — PASS

Body reading uses `io.LimitReader(r.Body, maxBodySize)` to prevent memory exhaustion from large request bodies (`context.go:193`). The `maxBodySize` is a configurable parameter passed to `AcquireContext`. Additionally, decompression bombs are rejected with a 100:1 ratio check (`context.go:206`).

### 8. Connection Limits — PASS

The reverse proxy transport enforces `MaxConnsPerHost: 100` (`proxy/target.go:182`) and `MaxIdleConns: 100` (`proxy/target.go:177`) to limit concurrent connections to backends. There is no per-IP connection limit at the WAF entry point, but the IP ACL layer provides auto-ban capabilities based on rate limit violations.

---

## Conclusion

Rate limiting is well-implemented with solid DoS protections. The primary finding is the lack of tenant isolation in rate limit bucket keys, which could allow one tenant's traffic to affect another's rate limits. All other checks pass.