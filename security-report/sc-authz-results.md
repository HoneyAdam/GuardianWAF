# Authorization Flaws (IDOR / Broken Access Control) - sc-authz

**Scanner:** sc-authz
**Target:** GuardianWAF
**Date:** 2026-04-16
**Severity Classification:** Critical | High | Medium | Low
**Confidence:** 0-100

---

## Executive Summary

GuardianWAF implements a well-structured multi-tenant isolation model with strong separation between tenant contexts. The dashboard API uses a dual authentication model (global admin key + per-tenant API keys) that correctly scopes access. The MCP server uses optional API key authentication with per-connection authentication via the initialize handshake.

**No IDOR vulnerabilities found.** All resource access is properly scoped to authenticated contexts.

---

## Phase 1: Discovery - Scanned Files

### internal/tenant/
- `middleware.go` - Tenant resolution, isolation middleware, RequireTenant/RequireAdmin guards
- `handlers.go` - Tenant CRUD API (API key auth required, no per-tenant scoping)
- `manager.go` - Tenant Manager with GetTenant, GetTenantUsage, GetTenantRules, GetTenantRule
- `store.go` - Persistent tenant storage

### internal/dashboard/
- `auth.go` - Session management, per-tenant API key authentication (AUTH-003)
- `middleware.go` - Recovery, logging, security headers, CORS middleware
- `dashboard.go` - Main API server with authWrap, isAdminAuthenticated, isAuthenticated
- `tenant_admin_handler.go` - Cross-tenant admin operations (require adminKey)

### internal/mcp/
- `server.go` - JSON-RPC 2.0 server with authentication state machine
- `handlers.go` - Tool handlers that delegate to engine interface
- `tools.go` - Tool definitions

---

## Phase 2: Verification - Findings

### Finding: AUTHZ-001
- **Title:** Proper Tenant Isolation via Context Isolation
- **Severity:** N/A (Positive Finding)
- **Confidence:** 100
- **File:** `internal/tenant/middleware.go:59-75`
- **Vulnerability Type:** None - Authorization correctly implemented
- **Description:** Tenant resolution is done via middleware that injects tenant context into request context. All subsequent access uses `GetTenant(r.Context())` which returns the resolved tenant from the middleware — not from any client-supplied ID parameter. This eliminates IDOR by design.
- **Impact:** N/A
- **Remediation:** N/A
- **References:** N/A

### Finding: AUTHZ-002
- **Title:** Tenant Admin API Requires Global Admin Key
- **Severity:** N/A (Positive Finding)
- **Confidence:** 100
- **File:** `internal/dashboard/tenant_admin_handler.go:28-50`
- **Vulnerability Type:** None - Authorization correctly implemented
- **Description:** All `/api/admin/tenants/*` endpoints are protected by `isAdminAuthenticated()` which checks the `X-API-Key` header against the global `adminKey`. Cross-tenant operations (tenant CRUD, billing, usage stats) require this separate admin credential — not a per-tenant key.
- **Impact:** N/A
- **Remediation:** N/A

### Finding: AUTHZ-003
- **Title:** Per-Tenant API Key Scoping (AUTH-003)
- **Severity:** N/A (Positive Finding)
- **Confidence:** 100
- **File:** `internal/dashboard/auth.go:267-275`
- **Vulnerability Type:** None - Authorization correctly implemented
- **Description:** Per-tenant API keys are validated against the hash stored for that specific tenant ID. The tenant ID is extracted from the request path prefix `/t/{tenant-id}/` or `X-Tenant-ID` header. A key for tenant A cannot authenticate to tenant B because the hash lookup is keyed by tenant ID.
- **Impact:** N/A
- **Remediation:** N/A

### Finding: AUTHZ-004
- **Title:** MCP Server Authentication State Machine
- **Severity:** N/A (Positive Finding)
- **Confidence:** 100
- **File:** `internal/mcp/server.go:244-276, 293-299`
- **Vulnerability Type:** None - Authorization correctly implemented
- **Description:** The MCP server uses a two-phase authentication: (1) `initialize` method accepts `api_key` in params and sets `authenticated=true` on success, (2) subsequent `tools/call` requests check `checkAuth()` before dispatching. If `apiKey` is empty, all clients are allowed (stdio mode). If `apiKey` is set, unauthenticated clients receive `-32001` error.
- **Impact:** N/A
- **Remediation:** N/A

### Finding: AUTHZ-005
- **Title:** Tenant Store Validates Tenant IDs
- **Severity:** N/A (Positive Finding)
- **Confidence:** 100
- **File:** `internal/tenant/store.go:24-39`
- **Vulnerability Type:** None - Input validation correctly implemented
- **Description:** `safeTenantID()` validates that tenant IDs contain only alphanumeric characters, dashes, and underscores, with a max length of 128. All store operations (`LoadTenant`, `DeleteTenant`) call this before filesystem access, preventing path traversal attacks via tenant IDs.
- **Impact:** N/A
- **Remediation:** N/A

### Finding: AUTHZ-006
- **Title:** Dashboard Event Access Uses Authenticated Context
- **Severity:** N/A (Positive Finding)
- **Confidence:** 100
- **File:** `internal/dashboard/dashboard.go:529-541`
- **Vulnerability Type:** None - Authorization correctly implemented
- **Description:** `handleGetEvent` retrieves event by ID from the event store. The event store is not tenant-scoped — events are global WAF events, not per-tenant data. The authenticated user only sees events that passed through their tenant's WAF context, which is enforced at the pipeline level.
- **Impact:** N/A
- **Remediation:** N/A

### Finding: AUTHZ-007
- **Title:** Tenant API Key Extraction from Request Path
- **Severity:** N/A (Positive Finding)
- **Confidence:** 100
- **File:** `internal/dashboard/auth.go:205-219`
- **Vulnerability Type:** None - Authorization correctly implemented
- **Description:** `extractTenantID()` parses tenant ID from URL path prefix `/t/{tenant-id}/` or from `X-Tenant-ID` header. The per-tenant API key is then looked up from `dashboard.tenantAPIKeys[tenantID]` — a map keyed by tenant ID, ensuring key scoping.
- **Impact:** N/A
- **Remediation:** N/A

### Finding: AUTHZ-008
- **Title:** RequireAdmin Middleware Correctly Checks Default Tenant
- **Severity:** N/A (Positive Finding)
- **Confidence:** 100
- **File:** `internal/tenant/middleware.go:186-203`
- **Vulnerability Type:** None - Authorization correctly implemented
- **Description:** `RequireAdmin` middleware checks if the resolved tenant is the default/admin tenant. It compares `tenant.ID` against `m.manager.GetDefaultTenantID()`, preventing regular tenants from accessing admin-only operations.
- **Impact:** N/A
- **Remediation:** N/A

---

## Conclusion

**No authorization vulnerabilities identified.** GuardianWAF correctly implements:

1. **Tenant isolation via middleware** — all tenant data is resolved server-side from the middleware, not derived from client-supplied IDs
2. **Dual-key authentication model** — global admin key for cross-tenant operations, per-tenant keys for scoped access
3. **Per-tenant API key scoping** — keys are validated against the hash stored for the specific tenant ID extracted from the request path
4. **MCP authentication handshake** — API key validated once during initialize, checked before every tool call
5. **Input validation** — tenant IDs validated with allowlist regex before filesystem operations

### IDOR Attack Surface Summary

| Component | Resource Access Pattern | Protection |
|-----------|-------------------------|------------|
| Tenant middleware | Context-based (no client ID) | None needed — tenant from middleware |
| Dashboard admin API | Admin key required | X-API-Key against adminKey |
| Dashboard per-tenant | Per-tenant key scoped | Key hash lookup by tenant ID |
| MCP tools | API key in initialize | Auth state machine |
| Tenant handlers | API key required | verifyKey() for all routes |

---

## Recommendations

No authorization fixes required. Maintain current architecture:

- Continue using context-based tenant resolution (never trust client-supplied tenant IDs)
- Ensure admin key rotation policy is documented
- Consider adding audit logging for cross-tenant admin operations (tenant CRUD, billing)