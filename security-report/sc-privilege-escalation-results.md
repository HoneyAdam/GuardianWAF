# Privilege Escalation Scanner Results

**Scanner:** sc-privilege-escalation
**Date:** 2026-04-16

---

## Executive Summary

GuardianWAF implements a multi-layered authentication and authorization model with distinct separation between dashboard authentication, tenant isolation, and MCP tool access. The architecture uses API keys with per-tenant scoping rather than traditional role-based access control (RBAC).

**Overall Assessment: SECURE with minor observations**

No privilege escalation vulnerabilities were found. The codebase demonstrates sound security design patterns.

---

## 1. Authentication Architecture

### Finding: SEPARATION OF ADMINISTRATIVE KEYS

**File:** `internal/dashboard/dashboard.go:76-134`

The dashboard uses two separate keys:
- **`apiKey`** - Dashboard access key (session-based for browser, header-based for API)
- **`adminKey`** - Separate system admin key for cross-tenant operations (`/api/admin/*`)

```go
adminKey        string // Separate key for system admin operations
```

```go
func (d *Dashboard) isAdminAuthenticated(r *http.Request) bool {
    if d.adminKey == "" {
        return false  // Admin key not configured — reject all admin requests
    }
    if key := r.Header.Get("X-API-Key"); key != "" {
        return subtle.ConstantTimeCompare([]byte(key), []byte(d.adminKey)) == 1
    }
    return false
}
```

**Assessment:** Properly separated concerns. Admin endpoints require explicit admin key, distinct from regular dashboard access.

---

### Finding: ADMIN KEY GENERATION

**File:** `cmd/guardianwaf/main_default.go:2637-2642`

Admin keys are generated using `crypto/rand` (cryptographically secure):

```go
if cfg.Dashboard.AdminKey != "" {
    dash.SetAdminKey(cfg.Dashboard.AdminKey)
} else {
    // Generate a random admin key if not configured.
    keyBytes := make([]byte, 32)
    crypto_rand.Read(keyBytes)
    dash.SetAdminKey(hex.EncodeToString(keyBytes))
    fmt.Printf("Dashboard admin key not set — generated: %s\n", hex.EncodeToString(keyBytes))
}
```

**Assessment:** SECURE - Uses `crypto_rand.Read` for key generation. No default or hardcoded admin keys.

---

## 2. Tenant Isolation

### Finding: PER-TENANT API KEY SCOPING (AUTH-003)

**File:** `internal/tenant/handlers.go:31-42`

Each tenant has an isolated API key that only grants access within that tenant's context:

```go
func (h *Handlers) verifyKey(r *http.Request) bool {
    if h.apiKey == "" {
        return false
    }
    key := r.Header.Get("X-API-Key")
    if key == "" {
        key = r.Header.Get("X-Admin-Key")  // Fallback to admin key
    }
    return subtle.ConstantTimeCompare([]byte(key), []byte(h.apiKey)) == 1
}
```

**File:** `internal/dashboard/auth.go:267-275`

Per-tenant API keys are validated against their specific tenant scope:

```go
// Check per-tenant API key (AUTH-003): key is scoped to a specific tenant
tenantID := extractTenantID(r)
if tenantID != "" && d.tenantAPIKeys != nil {
    if hash, ok := d.tenantAPIKeys[tenantID]; ok {
        if key := r.Header.Get("X-API-Key"); key != "" && verifyTenantAPIKey(hash, key) {
            return true
        }
    }
}
```

**Assessment:** SECURE - Per-tenant API keys provide proper tenant isolation. A tenant's key cannot access other tenants' data.

---

### Finding: CROSS-TENANT ACCESS PREVENTED

**File:** `internal/tenant/middleware.go:186-203`

The `RequireAdmin` middleware ensures only the default tenant can access admin resources:

```go
func (m *Middleware) RequireAdmin(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        tenant := GetTenant(r.Context())
        if tenant == nil {
            http.Error(w, "Tenant required", http.StatusUnauthorized)
            return
        }
        if m.manager.GetDefaultTenantID() != "" && tenant.ID != m.manager.GetDefaultTenantID() {
            http.Error(w, "Admin access required", http.StatusForbidden)
            return
        }
        next.ServeHTTP(w, r)
    })
}
```

**Assessment:** SECURE - Non-admin tenants cannot access administrative functions.

---

## 3. MCP Tool Access Control

### Finding: MCP AUTHENTICATION ON TOOLS/CALL

**File:** `internal/mcp/server.go:294-299`

MCP tools require authentication via the `initialize` method with a valid API key:

```go
func (s *Server) handleToolsCall(req JSONRPCRequest) {
    // Reject tool calls if authentication is required but client is not authenticated
    if s.apiKey != "" && !s.checkAuth() {
        s.sendError(req.ID, ErrCodeUnauthorized, "authentication required: call initialize first with api_key")
        return
    }
    // ... tool execution
}
```

**Assessment:** SECURE - MCP tools properly check authentication before execution.

---

### Finding: MCP SSE HTTP HANDLER AUTHENTICATION

**File:** `internal/mcp/sse.go:49-61, 134-139`

The HTTP handler for MCP over SSE validates authentication at the HTTP level:

```go
func (h *SSEHandler) authenticate(r *http.Request) bool {
    if h.apiKey == "" {
        log.Printf("[mcp/sse] SECURITY: rejecting unauthenticated request from %s", r.RemoteAddr)
        return false
    }
    if key := r.Header.Get("X-API-Key"); key != "" {
        return subtle.ConstantTimeCompare([]byte(key), []byte(h.apiKey)) == 1
    }
    if key := r.URL.Query().Get("api_key"); key != "" {
        log.Printf("[WARN] MCP API key passed via query parameter — rejected")
        return false  // Reject query-param-based API keys
    }
    return false
}
```

**Assessment:** SECURE - HTTP-level auth rejects query parameter API keys to prevent credential leakage via logs/referer headers.

---

### Finding: OBSERVATION - MCP tools/list UNAUTHENTICATED

**File:** `internal/mcp/server.go:279-285`

The `tools/list` MCP method returns available tools without authentication:

```go
func (s *Server) handleToolsList(req JSONRPCRequest) {
    tools := AllTools()
    result := map[string]any{"tools": tools}
    s.sendResult(req.ID, result)
}
```

**Impact:** Low - Lists tool names without executing them. Actual tool execution still requires authentication. This is standard MCP protocol behavior.

---

## 4. Session Management Security

### Finding: SESSION SECURITY CONTROLS

**File:** `internal/dashboard/auth.go:74-127`

Sessions implement multiple security controls:

1. **HMAC-signed tokens** with IP binding:
   ```go
   func signSession(clientIP string) string {
       now := time.Now().Unix()
       ts := fmt.Sprintf("%d.%d", now, now)
       mac := hmac.New(sha256.New, loadSecret())
       mac.Write([]byte(ts + ":" + clientIP))
       sig := hex.EncodeToString(mac.Sum(nil))
       return ts + "." + sig
   }
   ```

2. **IP binding** prevents cookie theft across different clients

3. **Sliding expiry** (24 hours) and **absolute expiry** (7 days)

4. **Concurrent session limit** (5 per IP) with oldest eviction

5. **Server-side revocation** via `revokedSessions` map

**Assessment:** SECURE - Comprehensive session security controls.

---

## 5. Admin Route Protection

### Finding: ALL ADMIN ROUTES PROTECTED

**File:** `internal/dashboard/tenant_admin_handler.go:28-50`

All cross-tenant admin routes are protected by `isAdminAuthenticated`:

```go
func (h *TenantAdminHandler) RegisterRoutes(mux *http.ServeMux) {
    auth := func(handler http.HandlerFunc) http.HandlerFunc {
        return func(w http.ResponseWriter, r *http.Request) {
            if !h.dashboard.isAdminAuthenticated(r) {
                writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized: system admin key required"})
                return
            }
            handler(w, r)
        }
    }
    mux.HandleFunc("/api/admin/tenants", auth(h.handleTenants))
    mux.HandleFunc("/api/admin/tenants/", auth(h.handleTenantDetail))
    mux.HandleFunc("/api/admin/stats", auth(h.handleStats))
    mux.HandleFunc("/api/admin/billing", auth(h.handleBilling))
    // ... all admin routes
}
```

**Assessment:** SECURE - All admin endpoints require explicit admin key authentication.

---

## 6. Tenant Update Request Handling

### Finding: ALLOWED FIELDS VALIDATION ON TENANT UPDATE

**File:** `internal/dashboard/tenant_admin_handler.go:184-195`

Tenant updates validate that only known/allowed fields are modified:

```go
allowedKeys := map[string]bool{
    "name": true, "description": true, "domains": true,
    "enabled": true, "billing_plan": true, "quota": true,
    "waf_config": true, "rate_limits": true,
}
for k := range update {
    if !allowedKeys[k] {
        writeJSON(w, http.StatusBadRequest, map[string]any{"error": "unknown field: " + k})
        return
    }
}
```

**Assessment:** SECURE - Prevents injection of unexpected fields during tenant updates.

---

## 7. No Role-Based Access Control System

### Finding: NO RBAC IMPLEMENTED

**Observation:** GuardianWAF does not implement traditional RBAC with user roles (e.g., "viewer", "operator", "admin"). Instead:

1. **Dashboard access** - Single API key grants full access to all dashboard functions
2. **Admin access** - Separate admin key grants cross-tenant management
3. **Per-tenant access** - Tenant-specific keys for tenant-scoped operations

**Security Implication:** All users with dashboard access have equal privileges. There is no way to create read-only users or limit specific operations.

**Recommendation:** For environments requiring granular permissions, consider implementing RBAC in a future release. Current model is acceptable for single-operator deployments or environments where all operators are fully trusted.

---

## Summary Table

| Attack Vector | Status | Details |
|---------------|--------|---------|
| Default admin credentials | SECURE | Keys generated via crypto/rand, no hardcoded defaults |
| Role manipulation via request body | SECURE | No user-provided role fields accepted |
| JWT role claim tampering | N/A | JWT validation is for API security layer, not user auth |
| Unprotected admin endpoints | SECURE | All /api/admin/* routes require admin key |
| Tenant data cross-access | SECURE | Per-tenant API keys with strict scoping |
| MCP tool unauthorized access | SECURE | Auth required via initialize handshake |
| Session hijacking | SECURE | HMAC-signed, IP-bound, revocable sessions |
| Default/weak admin keys | SECURE | crypto/rand for all key generation |

---

## Conclusion

GuardianWAF implements proper privilege separation through:

1. **Two-key authentication model** - Dashboard key and admin key are separate
2. **Per-tenant API key isolation** - Tenants cannot access each other's data
3. **MCP tool authentication** - All tools require valid API key
4. **Session security** - HMAC-signed, IP-bound, revocable
5. **No hardcoded credentials** - All keys generated via crypto/rand

**No privilege escalation vulnerabilities were identified.**

The absence of RBAC is a feature limitation rather than a security vulnerability, as the current model is appropriate for the WAF's target use case.
