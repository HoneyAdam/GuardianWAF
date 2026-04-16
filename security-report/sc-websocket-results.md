# WebSocket Security Scan Results

**Scanner:** sc-websocket (WebSocket Security)
**Target:** `internal/layers/websocket/`
**Date:** 2026-04-16
**Confidence:** High

---

## Summary

| Finding | Severity | Status |
|---------|----------|--------|
| WS-001 | Critical | Open |
| WS-002 | Medium | Open |

---

## Finding: WS-001

- **Title:** WebSocket Origin Validation Bypass in Default Configuration
- **Severity:** Critical
- **Confidence:** 90
- **File:** `internal/layers/websocket/websocket.go:187-193`
- **Vulnerability Type:** CWE-1385 (Missing Origin Validation in WebSocket)

### Description

The `ValidateHandshake` function only performs origin validation when `AllowedOrigins` is explicitly configured with at least one entry:

```go
// Check origin if allowed origins configured
if len(s.config.AllowedOrigins) > 0 {
    origin := r.Header.Get("Origin")
    if !s.isAllowedOrigin(origin, r) {
        return fmt.Errorf("origin not allowed: %s", origin)
    }
}
```

When `AllowedOrigins` is empty (the default configuration), no origin check is performed, allowing cross-origin WebSocket connections from any origin.

### Impact

Cross-site WebSocket hijacking (CSWSH). An attacker can trick a user's browser into establishing a WebSocket connection to the WAF-protected server from a malicious page. If the application relies on WebSocket for sensitive data transmission (e.g., authentication via cookies), the attacker can intercept this data.

### Evidence

- Default config in `websocket.go:52-68` sets `AllowedOrigins: []string{}`
- `isAllowedOrigin` function (lines 224-269) has correct same-origin policy logic but is never invoked when `AllowedOrigins` is empty
- The test `TestIsAllowedOrigin_AllowAll` (websocket_test.go:146-164) confirms the correct behavior exists but is dead code in the default configuration

### Remediation

Remove the conditional check so origin validation is always performed:

```go
origin := r.Header.Get("Origin")
if !s.isAllowedOrigin(origin, r) {
    return fmt.Errorf("origin not allowed: %s", origin)
}
```

The `isAllowedOrigin` function already handles the case where `AllowedOrigins` is empty by enforcing same-origin policy.

### References

- https://cwe.mitre.org/data/definitions/1385.html
- https://portswigger.net/web-security/websocket-attacks

---

## Finding: WS-002

- **Title:** Inconsistent Hardcoded Frame Size Limit
- **Severity:** Medium
- **Confidence:** 85
- **File:** `internal/layers/websocket/websocket.go:539`
- **Vulnerability Type:** CWE-20 (Improper Input Validation)

### Description

The `ParseFrame` function uses a hardcoded 2MB limit for incoming frame payloads:

```go
const maxFramePayload = 2 * 1024 * 1024
if payloadLen > maxFramePayload {
    return nil, fmt.Errorf("frame payload too large: %d bytes (max %d)", payloadLen, maxFramePayload)
}
```

However, the configurable `MaxFrameSize` defaults to 1MB. This creates an inconsistency where a 1.5MB frame is accepted by `ParseFrame` but rejected by `ValidateFrame` (line 400) which uses the 1MB limit.

### Impact

- Defense-in-depth is weakened because the initial parse accepts larger frames than intended
- Could cause confusion during debugging and incident response
- Potential for larger payloads to consume more memory before being rejected

### Evidence

- Config default (`websocket.go:56`): `MaxFrameSize: 1 * 1024 * 1024` (1MB)
- Hardcoded parse limit (`websocket.go:539`): `maxFramePayload = 2 * 1024 * 1024` (2MB)
- Validation check (`websocket.go:400-401`): uses `s.config.MaxFrameSize`

### Remediation

Change the hardcoded limit to match or be less than the configurable limit:

```go
const maxFramePayload = 1 * 1024 * 1024 // Match MaxFrameSize default
```

Or make it configurable and documented.

### References

- https://cwe.mitre.org/data/definitions/20.html

---

## Additional Observations

### No Subprotocol Validation
The implementation does not validate or restrict `Sec-WebSocket-Protocol` headers. If the application requires specific subprotocols, this should be enforced.

### No Extension Validation
While `Sec-WebSocket-Extensions` header is accepted, there is no validation against the `BlockedExtensions` config. Only path extensions are checked.

### README Documentation Inconsistency
Line 26 of `internal/layers/websocket/README.md` states:
```yaml
allowed_origins:                # Empty = allow all
```

This is incorrect. The code implements "Empty = same-origin policy" (reject cross-origin), not "allow all". The comment in `isAllowedOrigin` (line 225) correctly states: "Default to same-origin policy: reject cross-origin entirely"

---

## Security Checklist

| Control | Status | Notes |
|---------|--------|-------|
| Origin Validation | Partial | Only when AllowedOrigins configured |
| Connection Limits | Implemented | MaxConcurrentPerIP |
| Frame Size Limits | Implemented | Config + hardcoded 2MB parse limit |
| Rate Limiting | Implemented | Token bucket per connection |
| Message Validation | Implemented | Payload scanning for threats |
| UTF-8 Validation | Implemented | IsValidUTF8 function |
| Idle Timeout | Implemented | CleanupStaleConnections |
| WebSocket Hijacking Protection | Partial | Only when origins configured |

---

## Files Scanned

- `internal/layers/websocket/websocket.go` (784 lines)
- `internal/layers/websocket/layer.go` (114 lines)
- `internal/layers/websocket/handler.go` (90 lines)
- `internal/layers/websocket/websocket_test.go` (809 lines)
- `internal/layers/websocket/README.md`
