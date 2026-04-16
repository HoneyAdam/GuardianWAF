# SC-CORS Results

**Scanner:** sc-cors (CORS Misconfiguration)
**Date:** 2026-04-16
**Files Scanned:** `internal/layers/cors/cors.go`, `internal/engine/engine.go`, `guardianwaf.yaml`

---

## Findings Summary

| ID | Severity | Confidence | Issue |
|----|----------|-----------|-------|
| CORS-001 | Medium | 90 | Wildcard origin (`*`) in default config |
| CORS-002 | Low | 85 | Missing `Vary: Origin` header |

---

## Finding: CORS-001

**Title:** CORS Misconfiguration - Wildcard Origin in Default Config

**Severity:** Medium
**Confidence:** 90/100
**File:** `guardianwaf.yaml:91`
**Vulnerability Type:** CWE-942 (Permissive Cross-domain Policy)

**Description:**
The default configuration uses `*` (wildcard) as an allowed origin:
```yaml
cors:
  enabled: true
  allowed_origins:
    - "*"
```

**Impact:**
- Browsers ignore `Access-Control-Allow-Credentials: true` when `Access-Control-Allow-Origin: *` is set
- Any website can make cross-origin requests to protected APIs
- Sensitive data exposed to untrusted cross-origin requests

**Current Mitigations:**
- `allow_credentials: false` is set in default config (credentials are not enabled with wildcard)
- CORS layer uses origin reflection only for allowlisted origins (lines 247, 265 in cors.go)
- Null origin is rejected when credentials are enabled (line 127-129 in cors.go)

**Remediation:**
Replace wildcard with explicit origin allowlist:
```yaml
cors:
  allowed_origins:
    - "https://app.example.com"
    - "https://admin.example.com"
```

**Note:** This finding applies to the default config file. Production deployments should override `allowed_origins` with a strict allowlist.

---

## Finding: CORS-002

**Title:** CORS Misconfiguration - Missing Vary: Origin Header

**Severity:** Low
**Confidence:** 85/100
**File:** `internal/engine/engine.go:423-441`
**Vulnerability Type:** CWE-942 (Permissive Cross-domain Policy)

**Description:**
The CORS response hook (`applyCORSHook`) does not set the `Vary: Origin` header. When multiple origins are allowed and responses vary based on origin, caches may serve wrong-origin responses.

**Current Code:**
```go
func applyCORSHook(w http.ResponseWriter, metadata map[string]any) {
    if headers, ok := metadata["cors_preflight_headers"].(map[string]string); ok {
        for k, v := range headers {
            w.Header().Set(k, v)
        }
        return
    }
    // Regular CORS headers...
}
```

**Impact:**
- Caching proxies may serve CORS responses to wrong origins
- Low severity since credential-based CORS is disabled in default config
- Primarily affects cached responses with varying CORS policies

**Remediation:**
Add `Vary: Origin` header in `applyCORSHook`:
```go
w.Header().Set("Vary", "Origin")
```

---

## Security Assessment

| Aspect | Status | Notes |
|--------|--------|-------|
| Wildcard + Credentials | PASS | Credentials disabled when wildcard used |
| Null Origin | PASS | Rejected when credentials enabled (line 127-129) |
| Reflected Origin | PASS | Only reflected for allowlisted origins |
| Wildcard Patterns | PASS | Proper regex anchoring (scheme forced to https) |
| Vary Header | WARN | Missing, but low risk with current config |
| Preflight Caching | PASS | MaxAge set to 86400s in default config |

---

## Conclusion

The CORS implementation is **reasonably secure** with the default configuration:
- Credentials are disabled (so wildcard is less dangerous)
- Null origin is properly rejected with credentials
- Origin reflection only occurs for allowlisted origins
- Wildcard patterns properly enforce HTTPS scheme

**Primary concern:** The default config uses `*` wildcard, which should be replaced with an explicit allowlist in production. This is flagged as Medium severity.

**References:**
- https://cwe.mitre.org/data/definitions/942.html
- https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS
