# Authorization (AuthZ) Security Scan Results

**Target:** GuardianWAF - Pure Go WAF Codebase
**Date:** 2026-04-15
**Scan Type:** Authorization Flaws

---

## Summary

Multiple authorization vulnerabilities were identified, including missing tenant isolation in admin APIs, lack of JWT tenant claim validation, no API key tenant scoping, and an unauthenticated MCP server exposing privileged operations.

---

## Findings

### [CRITICAL] Missing Tenant Authorization in Admin API - Any Authenticated User Can Manage All Tenants

- **Category:** IDOR (Insecure Direct Object Reference) / Missing Authorization Checks
- **Location:** `internal/dashboard/tenant_admin_handler.go:26-48`, `internal/dashboard/tenant_admin_handler.go:63-88`
- **Description:**
  The `TenantAdminHandler` registers admin routes (`/api/admin/tenants`, `/api/admin/tenants/{id}`, `/api/admin/usage/{id}`, `/api/admin/billing/{id}`, `/api/admin/tenants/rules/{tenantID}/{ruleID}`, etc.) that perform tenant management operations (create, read, update, delete, regenerate API keys, manage billing, manage rules).

  All these routes only check if the request is **authenticated** via `h.dashboard.isAuthenticated(r)` (line 29) - they do NOT verify that the authenticated user is authorized to manage the **target** tenant. There is no per-tenant user concept or tenant-scoped authorization.

  Any user who holds a valid dashboard session cookie or API key can:
  - List all tenants
  - View any tenant's details, usage, and billing
  - Update any tenant's configuration
  - Delete any tenant
  - Regenerate any tenant's API key
  - Add/update/delete rules for any tenant

  The `RequireAdmin` middleware in `internal/tenant/middleware.go:186-203` only checks if the tenant ID matches the **default tenant ID**, but the dashboard admin API does not use this middleware - it uses its own `auth` wrapper that only checks authentication, not admin status.

- **Remediation:**
  Implement per-tenant user authentication with role-based access control (RBAC):
  1. Add a `TenantAdmin` concept where each tenant has its own admin credentials
  2. Require that the authenticated user belongs to the target tenant before allowing management operations
  3. Alternatively, use the dashboard API key per-tenant, not globally

---

### [HIGH] JWT Validation Does Not Check Tenant Claims

- **Category:** Missing Authorization Checks
- **Location:** `internal/layers/apisecurity/jwt.go:184-209`, `internal/layers/apisecurity/apisecurity.go:89-116`
- **Description:**
  The JWT validator in `jwt.go` validates standard claims (`exp`, `nbf`, `iss`, `aud`) but does NOT validate any tenant-specific claims. When a JWT is validated in `apisecurity.go`, the tenant ID is not extracted from the JWT claims and no authorization check is performed to verify the JWT subject/tenant matches the request's tenant context.

  This means a valid JWT issued for Tenant A can be used to access resources for Tenant B if the WAF is configured to trust the same issuer.

  The JWT claims are stored in `ctx.Metadata["jwt_claims"]` and `ctx.Metadata["auth_subject"]` but these are never used for tenant authorization.

- **Remediation:**
  1. Define a `tenant_id` or `tenant` claim in JWT configuration
  2. During JWT validation, extract the tenant claim and verify it matches the resolved tenant context
  3. Block requests where the JWT tenant claim doesn't match the request's tenant

---

### [HIGH] API Key Validation Has No Tenant Scoping

- **Category:** Missing Authorization Checks
- **Location:** `internal/layers/apisecurity/apikey.go:64-100`, `internal/layers/apisecurity/apisecurity.go:119-147`
- **Description:**
  The `APIKeyConfig` struct (`internal/layers/apisecurity/apikey.go:12-20`) supports `AllowedPaths` for path-based restrictions but has NO `TenantID` or `Scope` field. API keys are validated purely based on the key hash match and path restrictions.

  When the API Security layer processes a request (`apisecurity.go:119-147`), it extracts the API key, validates it, and stores `keyConfig.Name` and `keyConfig.RateLimit` in metadata, but there is no tenant ID validation. An API key valid for one tenant can be used from any tenant context.

- **Remediation:**
  1. Add `TenantID` field to `APIKeyConfig`
  2. During API key validation, verify the key's `TenantID` matches the request's tenant context
  3. Reject keys that don't have a matching tenant scope

---

### [HIGH] Dashboard API Key Provides System-Wide Admin Access

- **Category:** Privilege Escalation / Missing Authorization
- **Location:** `internal/dashboard/auth.go:120-145`, `internal/dashboard/dashboard.go:131-197`
- **Description:**
  The dashboard uses a single global API key (`apiKey` field in `Dashboard` struct) for all authentication. This key grants full access to:
  - All dashboard API endpoints including `/api/admin/tenants`
  - All WAF configuration changes
  - All security settings (IP ACLs, rules, etc.)

  There is no concept of per-tenant admin users. The `RequireAdmin` middleware exists (`tenant/middleware.go:186-203`) but is NOT applied to dashboard routes. All dashboard routes use `authWrap` which only checks if the request is authenticated, not if the user has admin privileges for any particular tenant.

- **Remediation:**
  1. Implement per-tenant admin credentials
  2. Apply the `RequireAdmin` middleware to tenant admin routes
  3. Verify the authenticated tenant matches the target tenant for all tenant-specific operations

---

### [MEDIUM] MCP Server Has No Authentication or Authorization

- **Category:** Missing Authorization Checks
- **Location:** `internal/mcp/server.go:106-116`, `internal/mcp/handlers.go:1-490`
- **Description:**
  The MCP server exposes 44+ privileged tools including:
  - `guardianwaf_add_blacklist` / `guardianwaf_remove_blacklist` - manage IP blocking
  - `guardianwaf_add_whitelist` / `guardianwaf_remove_whitelist` - manage IP whitelisting
  - `guardianwaf_set_mode` - change WAF enforcement mode
  - `guardianwaf_get_config` - read full configuration
  - `guardianwaf_add_ratelimit` / `guardianwaf_remove_ratelimit` - manage rate limits
  - `guardianwaf_add_webhook` / `guardianwaf_remove_webhook` - manage alerting
  - `guardianwaf_get_events` - read all security events

  There is **no authentication** on the MCP server - any process that can send JSON-RPC requests to the server (stdio) can execute all these privileged operations.

- **Remediation:**
  1. Add authentication to the MCP server (e.g., API key or token)
  2. Implement per-tool authorization based on caller permissions
  3. Document that the MCP server should only be accessible to trusted local processes

---

### [LOW] Session Binding Uses IP Address Only

- **Category:** Session Security
- **Location:** `internal/dashboard/auth.go:60-105`
- **Description:**
  Session tokens are HMAC-signed with the client IP address (`signSession` at line 62). If an attacker obtains a valid session token and can make requests from the same IP address (e.g., behind a shared NAT, or by spoofing X-Forwarded-For in environments that trust it), they can use the stolen session token.

  Additionally, the client IP extraction (`clientIPFromRequest` at line 108) falls back to `r.RemoteAddr` when X-Forwarded-For / X-Real-IP headers are not present. In reverse proxy scenarios where these headers ARE present, the code uses them without validating that the proxy is trusted.

- **Remediation:**
  1. Consider adding a secondary binding (e.g., User-Agent hash) to the session token
  2. Validate X-Forwarded-For against trusted proxy IPs
  3. Implement session invalidation on suspicious activity detection

---

### [INFO] Path Prefix Router Has No Authorization Check

- **Category:** Missing Authorization Checks
- **Location:** `internal/tenant/middleware.go:293-338`
- **Description:**
  `PathPrefixRouter` extracts tenant IDs from URL paths (e.g., `/tenant/abc123/api`) but provides no authorization check that the requesting user has access to that tenant. Any authenticated user could craft requests to `/tenant/{other_tenant_id}/...` paths if the proxy forwards them.

  This is mitigated by the fact that tenant routes are typically resolved before reaching the dashboard, but if the `PathPrefixRouter` is used for multi-tenant API routing, an authenticated tenant A user could potentially access tenant B's resources.

- **Remediation:**
  1. Add tenant context verification when using `PathPrefixRouter`
  2. Ensure the authenticated tenant matches the path-extracted tenant ID

---

## Recommendations

1. **Immediate:** Add tenant authorization checks to all tenant admin API handlers - verify authenticated tenant matches target tenant before operations
2. **Short-term:** Implement per-tenant admin users with RBAC
3. **Short-term:** Add tenant claim validation to JWT processing
4. **Medium-term:** Add tenant scoping to API key validation
5. **Medium-term:** Add authentication to MCP server
6. **Long-term:** Implement audit logging for all administrative operations