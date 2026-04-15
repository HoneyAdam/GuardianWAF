# CORS Security Scan Results

**Scanner:** sc-cors
**Target:** Pure Go WAF codebase
**Date:** 2026-04-15

---

## Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 1 |
| HIGH | 0 |
| MEDIUM | 0 |
| LOW | 0 |
| INFO | 0 |

---

### [CRITICAL] CORS Headers Never Applied to HTTP Responses

- **Category:** CORS Misconfiguration / Implementation Bug
- **Location:** `internal/layers/cors/cors.go:245-256`, `internal/engine/engine.go:407-413`
- **Description:** The CORS layer computes and stores CORS headers in context metadata (`cors_headers`, `cors_preflight_headers`, `cors_expose_headers`) but never actually writes them to HTTP responses. The CORS layer sets `cors_response_hook = true` (a boolean), but the engine's `applyResponseHook` function at `engine.go:407` looks for `response_hook` as a function type, not a boolean. Additionally, the response layer (`internal/layers/response/response.go`) does not handle CORS headers at all — it only manages security headers and data masking.

  As a result, even when CORS validation passes (origin is allowed, preflight is valid), the required `Access-Control-Allow-Origin`, `Access-Control-Allow-Credentials`, and other CORS headers are **never written to the HTTP response**. Browsers will not receive the headers, and cross-origin requests will fail.

- **Evidence:**
  - `cors.go:256`: `ctx.Metadata["cors_response_hook"] = true` — boolean flag, never checked by engine
  - `cors.go:284`: Same issue for preflight headers
  - `engine.go:408`: `if hook, ok := metadata["response_hook"]; ok { ... }` — looks for `response_hook`, not `cors_response_hook`
  - The response layer (`response.go:87`) only registers `response_hook` for security headers

- **Remediation:** Register a `response_hook` function in the CORS layer (similar to how the response layer does it at `response.go:87`) that writes the stored `cors_headers` or `cors_preflight_headers` to the HTTP response writer. Alternatively, integrate CORS header application into the response layer itself.

---

## Positive Security Findings

The following CORS security controls are correctly implemented:

- **No wildcard origin alone:** `AllowOrigins` does not support a bare `*` origin. The `compileWildcard` function (cors.go:62) always anchors the regex with `^` and requires a scheme and host pattern. A plain `*` in `AllowOrigins` would not match any origin.

- **Credentials with wildcard origin:** When `AllowCredentials: true`, the code reflects the **validated specific origin** (e.g., `https://evil.example.com`) rather than a wildcard (cors.go:246). Browsers reject `Access-Control-Allow-Credentials: true` with `Access-Control-Allow-Origin: *`, so reflecting the specific origin is correct.

- **Origin allowlist required:** Origins are validated against `AllowOrigins` allowlist (cors.go:131-151). If no match and `StrictMode` is enabled, the request is blocked with a score of 30.

- **Method allowlist on preflight:** Preflight requests validate `Access-Control-Request-Method` against `AllowMethods` whitelist (cors.go:187-205). Invalid methods block in strict mode.

- **Header allowlist on preflight:** Preflight requests validate `Access-Control-Request-Headers` against `AllowHeaders` whitelist (cors.go:207-230).

- **Null origin rejection:** `Origin: null` is rejected when `AllowCredentials: true` (cors.go:127-129), preventing sandbox iframe abuse.

- **Wildcard scheme restricted:** `*://*.example.com` is converted to `https://` only — HTTP is never allowed for wildcard schemes (cors.go:77-79).

---

**Conclusion:** 1 critical finding. The CORS validation logic is well-designed, but the implementation bug that prevents headers from being written to responses renders the CORS protection non-functional.
