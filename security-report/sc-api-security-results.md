# API Security Scan Results - GuardianWAF

**Scan Date:** 2026-04-15
**Target:** Pure Go WAF codebase with React dashboard
**Skill:** sc-api-security

---

## Summary

| Category | Status | Findings |
|----------|--------|----------|
| REST API security | Good | Proper auth on all protected routes |
| GraphQL security | Medium Risk | Introspection enabled by default |
| gRPC security | Good | API key auth on all endpoints |
| MCP server security | Low Risk | No auth (stdio transport assumed trusted) |
| SSE security | Good | Auth required, client cap enforced |
| Missing authentication | None | Health endpoint intentionally public |
| IDOR | Not Found | Admin routes use central auth |
| Mass assignment | Not Found | Allow-list validation on updateTenant |

---

## Detailed Findings

### [MEDIUM] GraphQL Introspection Enabled by Default

- **Category:** GraphQL Security
- **Location:** `internal/layers/graphql/layer.go:40`, `internal/config/defaults.go:965`
- **Description:** The `BlockIntrospection` configuration defaults to `false`, meaning GraphQL introspection queries (`__schema`, `__type`, `__typename`) are allowed by default. An attacker can query the schema to discover all types, fields, and operations without authentication.
- **Remediation:** Set `BlockIntrospection: true` by default in `DefaultConfig()` at `internal/layers/graphql/layer.go:47`, or require operators to explicitly enable introspection in production environments.

---

### [LOW] MCP Server Has No Built-in Authentication

- **Category:** MCP Server Security
- **Location:** `internal/mcp/server.go:162`, `internal/mcp/handlers.go`
- **Description:** The MCP JSON-RPC 2.0 server exposes 44 tools (add_blacklist, remove_blacklist, add_whitelist, set_mode, get_config, etc.) with no authentication mechanism. While the stdio transport is assumed to be local to the Claude Code session, a compromised process with stdio access could manipulate WAF settings, add/remove IP bans, change modes, or retrieve sensitive config.
- **Remediation:** Consider adding an `api_key` field to the MCP `Server` struct and require `X-API-Key` in the `initialize` request, similar to how the dashboard and gRPC handler implement authentication.

---

### [INFO] GraphQL Security Layer Has Good Protections

- **Category:** GraphQL Security
- **Location:** `internal/layers/graphql/layer.go:36-44`
- **Description:** Despite the default introspection setting, the GraphQL layer implements several security controls: `MaxDepth` (default 10), `MaxComplexity` (default 1000), `MaxAliases` (default 10), `MaxBatchSize` (default 5), and directive injection detection (`@skip`, `@include`, `@deprecated`). If `BlockIntrospection` is set to `true`, introspection queries are blocked with a score of 100.
- **Remediation:** None needed — layer is well-designed. Just ensure `BlockIntrospection` is enabled in production.

---

### [INFO] REST API Properly Protected

- **Category:** REST API Security
- **Location:** `internal/dashboard/dashboard.go:131-157`, `internal/dashboard/auth.go`
- **Description:** All `/api/v1/` routes except `/api/v1/health` require authentication via session cookie or `X-API-Key` header. API keys in query strings are explicitly rejected (prevents leakage via access logs/browser history). Login rate limiting: 5 attempts per 5 minutes, 15-minute lockout on failure. CSRF protection for cookie-authenticated state-changing requests (via `verifySameOrigin`). Constant-time comparison for API key verification.
- **Remediation:** None needed.

---

### [INFO] gRPC Handler Uses API Key Authentication

- **Category:** gRPC Security
- **Location:** `internal/layers/grpc/handler.go:28-41`
- **Description:** All gRPC endpoints (`/api/v1/grpc/stats`, `/api/v1/grpc/streams`, `/api/v1/grpc/services`) require `X-API-Key` header authentication via `subtle.ConstantTimeCompare`. Endpoints return 401 if key is missing or invalid.
- **Remediation:** None needed.

---

### [INFO] SSE Endpoint Properly Protected

- **Category:** SSE Security
- **Location:** `internal/dashboard/dashboard.go:157`, `internal/dashboard/dashboard.go:1796-1837`
- **Description:** `/api/v1/sse` requires authentication via `authWrap`. Maximum client limit (1000) is enforced atomically before client registration. Clients are removed from the client map on disconnect.
- **Remediation:** None needed.

---

### [INFO] Tenant API Uses Separate Key Auth

- **Category:** Multi-Tenant Security
- **Location:** `internal/tenant/handlers.go:31-42`, `internal/dashboard/tenant_admin_handler.go:27-35`
- **Description:** Tenant management endpoints use dedicated API key authentication (`X-API-Key` or `X-Admin-Key` header) separate from the dashboard key. Tenant ID validation rejects non-alphanumeric characters (except dash/underscore). `RegenerateAPIKey` requires admin authentication.
- **Remediation:** None needed.

---

### [INFO] No IDOR Found in Admin Routes

- **Category:** IDOR
- **Location:** `internal/dashboard/tenant_admin_handler.go`
- **Description:** Admin routes (`/api/admin/tenants/`, `/api/admin/usage/`, `/api/admin/billing/`) use the dashboard's central `authWrap` authentication. No tenant isolation issues found — each admin can only manage tenants via the manager which handles isolation.
- **Remediation:** None needed.

---

### [INFO] Mass Assignment Protection in Tenant Updates

- **Category:** Mass Assignment
- **Location:** `internal/dashboard/tenant_admin_handler.go:182-193`
- **Description:** `handleUpdateTenant` uses an allow-list of known fields (`name`, `description`, `domains`, `enabled`, `billing_plan`, `quota`, `waf_config`, `rate_limits`). Any unknown field returns a 400 error with "unknown field: <field>".
- **Remediation:** None needed.

---

### [INFO] SSRF Protection on Webhook and AI URLs

- **Category:** SSRF
- **Location:** `internal/dashboard/dashboard.go:372-375` (webhook), `internal/dashboard/ai_handlers.go:116-120` (AI endpoint)
- **Description:** Webhook URLs validated to require `https://` or `http://` scheme. AI endpoint URLs validated to reject localhost, loopback, private, link-local, and unspecified IPs. Both prevent SSRF via malicious webhook/AI configurations.
- **Remediation:** None needed.

---

### [INFO] Health Endpoint Intentionally Public

- **Category:** Missing Authentication
- **Location:** `internal/dashboard/dashboard.go:128-129`
- **Description:** `/api/v1/health` is not wrapped with `authWrap` because it returns only basic status information (`healthy`/`degraded`) and component states — no sensitive data. This is standard practice for Kubernetes readiness/liveness probes.
- **Remediation:** None needed — intentional design.

---

## Conclusion

The API security posture is generally strong. The primary finding is that GraphQL introspection is enabled by default, which could expose the schema in production environments. Operators should explicitly set `BlockIntrospection: true` in their configuration. The MCP server's lack of authentication is acceptable given the stdio transport assumption but could be improved with an opt-in API key.