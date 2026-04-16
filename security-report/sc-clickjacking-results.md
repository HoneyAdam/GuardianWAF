# Clickjacking Security Scan Results

**Scanner:** sc-clickjacking
**Date:** 2026-04-16
**Target:** GuardianWAF

---

## Summary

| Category | Status |
|----------|--------|
| X-Frame-Options (Dashboard) | PASS |
| X-Frame-Options (Response Layer) | WARNING |
| CSP frame-ancestors (Dashboard) | PASS |
| CSP frame-ancestors (Response Layer) | FAIL |
| clientside_csp_hook | FAIL |

---

## Findings

### 1. Dashboard Security Headers (PASS)

**File:** `internal/dashboard/middleware.go`

The dashboard's `SecurityHeadersMiddleware` correctly sets:

- `X-Frame-Options: DENY` (line 65)
- `Content-Security-Policy` with `frame-ancestors 'none'` (line 69)

**Assessment:** Dashboard is protected against clickjacking.

---

### 2. Response Layer Default X-Frame-Options (WARNING)

**File:** `internal/layers/response/headers.go:25`

```go
XFrameOptions: "SAMEORIGIN",
```

**Issue:** Default value is `SAMEORIGIN` instead of `DENY`.

- `SAMEORIGIN` allows framing from the same origin
- `DENY` prevents all framing entirely
- Recommendation: Use `DENY` for maximum clickjacking protection

**File:** `internal/config/defaults.go:130`

Config defaults also use `SAMEORIGIN`:

```go
XFrameOptions: "SAMEORIGIN",
```

---

### 3. Response Layer CSP Missing frame-ancestors (FAIL)

**File:** `internal/layers/response/headers.go:28`

```go
ContentSecurityPolicy: "default-src 'self'",
```

**Issue:** Default CSP does NOT include `frame-ancestors` directive.

- `X-Frame-Options` is the legacy clickjacking protection
- `frame-ancestors` is the modern CSP alternative
- Both should be present for defense-in-depth

---

### 4. clientside_csp_hook Never Applied (FAIL)

**File:** `internal/layers/clientside/layer.go:92`

The clientside layer registers a CSP hook:

```go
ctx.Metadata["clientside_csp_hook"] = func(w http.ResponseWriter) {
    if headerName != "" && headerValue != "" {
        w.Header().Set(headerName, headerValue)
        ...
    }
}
```

**Issue:** This hook is never called by the engine.

**File:** `internal/engine/engine.go:410-420`

```go
func applyResponseHook(w http.ResponseWriter, metadata map[string]any) {
    applyCORSHook(w, metadata)

    // Only response_hook is applied, NOT clientside_csp_hook
    if hook, ok := metadata["response_hook"]; ok {
        if fn, ok := hook.(func(http.ResponseWriter)); ok {
            fn(w)
        }
    }
}
```

**Impact:** The clientside layer's configurable CSP with `frame-ancestors` support is registered but never applied to responses.

---

### 5. SSE Endpoints Bypass Security Headers (INFO)

**File:** `internal/dashboard/middleware.go:57-61`

```go
if r.URL.Path == "/api/v1/sse" || r.URL.Path == "/mcp/sse" {
    next.ServeHTTP(w, r)
    return
}
```

SSE endpoints skip security headers. This is likely intentional for server-sent events compatibility, but worth reviewing.

---

## Recommendations

1. **Change response layer default to DENY:**
   - `internal/layers/response/headers.go:25`: `XFrameOptions: "DENY"`
   - `internal/config/defaults.go:130`: `XFrameOptions: "DENY"`

2. **Add frame-ancestors to response layer CSP:**
   - `internal/layers/response/headers.go:28`: `ContentSecurityPolicy: "default-src 'self'; frame-ancestors 'none'"`

3. **Integrate clientside_csp_hook into engine:**
   - Modify `applyResponseHook` in `internal/engine/engine.go` to also call `clientside_csp_hook`

4. **Review SSE endpoint bypass:**
   - Ensure SSE endpoints don't require clickjacking protection (they typically don't as they're not iframe-embeddable)

---

## Risk Level

**MEDIUM** - The dashboard is properly protected, but proxied responses through the response layer may have weaker clickjacking protection due to:
- Default `SAMEORIGIN` instead of `DENY`
- Missing `frame-ancestors` in default CSP
- Inactive clientside CSP hook
