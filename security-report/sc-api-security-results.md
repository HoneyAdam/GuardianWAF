# API Security Audit Results

## Scope
- Package: `internal/dashboard/`
- Files analyzed: `dashboard.go`, `auth.go`, `middleware.go`, `tenant_admin_handler.go`, `ai_handlers.go`, `docker_handlers.go`, `apivalidation_handlers.go`, `crs_handlers.go`, `dlp_handlers.go`, `virtualpatch_handlers.go`, `clientside_handlers.go`
- Endpoints: 60+ REST API endpoints across `/api/v1/*`, `/api/admin/*`, `/api/crs/*`, `/api/dlp/*`, `/api/apivalidation/*`, `/api/virtualpatch/*`, `/api/clientside/*`, `/debug/pprof/*`

---

## Finding: API-001

- **Title:** Debug pprof Endpoints Expose Sensitive Profiling Data
- **Severity:** High
- **Confidence:** 95
- **File:** `internal/dashboard/dashboard.go:218-222`
- **Vulnerability Type:** CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)
- **Description:** The `/debug/pprof/*` endpoints (heap, cpu, goroutine, threadcreate, trace profiles) are registered behind standard `authWrap`, but pprof can expose sensitive runtime information including:
  - Full memory contents via heap profiles
  - Active goroutine stacks (potential secrets in local variables)
  - Execution traces that may contain request data
  - Thread creation profiles revealing internal state
  While pprof is behind auth, it should be a separate high-privilege debug role, not standard API authentication.
- **Impact:** Authenticated attackers can extract sensitive data from pprof profiles including request contents, secrets in memory, and internal application state.
- **Remediation:** Create a separate `pprofAuth` middleware that requires a distinct `pprofKey` or require `adminKey` for all pprof endpoints. Alternatively, disable pprof endpoints in production by compile-time flag.
- **References:** https://owasp.org/API-Security/ - API Security Top 10 #3 (Excessive Data Exposure), https://pkg.go.dev/net/http/pprof

---

## Finding: API-002

- **Title:** No Rate Limiting on Protected API Endpoints
- **Severity:** Medium
- **Confidence:** 90
- **File:** `internal/dashboard/dashboard.go:166-213`
- **Vulnerability Type:** CWE-770 (Allocation of Resources Without Limits or Throttling)
- **Description:** While login attempts are rate-limited (5 attempts / 5 min lockout), all other API endpoints under `/api/v1/*` have no rate limiting. An attacker with valid credentials (or via session hijacking) could:
  - Exhaust event store with rapid event queries
  - Trigger expensive AI analysis repeatedly via `/api/v1/ai/analyze`
  - Export large datasets via `/api/v1/events/export` (up to 50,000 records per request)
  - Perform enumeration attacks on `/api/v1/events?offset=N`
  - Exhaust SSE broadcaster connections (capped at 1000 but no per-IP limit visible)
- **Impact:** Denial of service, resource exhaustion, data enumeration.
- **Remediation:** Add per-IP rate limiting middleware to all API endpoints. At minimum: 100 requests/minute for read endpoints, 10/minute for write endpoints, 1/minute for expensive operations (AI analysis, event export).
- **References:** https://owasp.org/API-Security/ - API Security Top 10 #4 (Lack of Resources & Rate Limiting)

---

## Finding: API-003

- **Title:** No Pagination Upper Bound on Offset-Based Enumeration
- **Severity:** Medium
- **Confidence:** 85
- **File:** `internal/dashboard/dashboard.go:470-526`
- **Vulnerability Type:** CWE-778 (Insufficient Logging and Monitoring) - partially applicable
- **Description:** The `/api/v1/events` endpoint uses offset-based pagination (`?limit=50&offset=0`). The `limit` is capped at 1000, but `offset` has no upper bound. An attacker can enumerate all events by incrementing offset. While events may not contain highly sensitive data, they reveal:
  - Client IP addresses (potential PII)
  - Attack patterns and WAF detection logic
  - Request paths and user agents
  - Scoring/threshold information useful for evasion
- **Impact:** Attackers can enumerate all historical security events to build attack profiles.
- **Remediation:** Implement cursor-based pagination (keyset) instead of offset. Alternatively, require authentication with audit logging for event access and alert on enumeration patterns.
- **References:** https://owasp.org/API-Security/ - API Security Top 10 #4 (Lack of Resources & Rate Limiting)

---

## Finding: API-004

- **Title:** Unvalidated Per-Tenant API Key Format Allows Weak Hashes
- **Severity:** Medium
- **Confidence:** 75
- **File:** `internal/dashboard/auth.go:221-236`
- **Vulnerability Type:** CWE-327 (Use of a Broken or Risky Cryptographic Algorithm)
- **Description:** The `verifyTenantAPIKey` function accepts legacy unsalted SHA256 hashes:
  ```go
  // Legacy unsalted hash
  expected := sha256.Sum256([]byte(apiKey))
  return subtle.ConstantTimeCompare([]byte(storedHash), []byte(hex.EncodeToString(expected[:]))) == 1
  ```
  The comparison uses `sha256([]byte(apiKey))` directly without salt. An attacker with the stored hash could perform offline brute force attacks. Modern per-tenant keys use salt$hash format, but legacy keys fall back to this weak pattern.
- **Impact:** If tenant API key hashes are leaked (e.g., from config backup), attackers can recover plaintext API keys via brute force.
- **Remediation:** Deprecate and migrate away from unsalted SHA256. On upgrade, regenerate all tenant API keys with the salt$hash format. Log warnings for tenants using legacy keys.
- **References:** https://owasp.org/API-Security/ - API Security Top 10 #2 (Broken Authentication)

---

## Finding: API-005

- **Title:** GeoIP Lookup Endpoint Has No Per-IP Rate Limiting
- **Severity:** Low
- **Confidence:** 80
- **File:** `internal/dashboard/dashboard.go:1706-1723`
- **Vulnerability Type:** CWE-770 (Allocation of Resources Without Limits or Throttling)
- **Description:** Both `handleGeoIPLookup` (GET) and `handleGeoIPLookupPost` (POST) endpoints perform GeoIP lookups without any rate limiting. While each lookup is inexpensive, an attacker could:
  - Use the endpoints as an oracle to discover which IPs are in the GeoIP database
  - Perform large-scale IP range scanning against the GeoIP service
  - Bypass IP-based rate limits by looking up attack infrastructure IPs
- **Impact:** Enables reconnaissance and potential abuse of GeoIP lookup service.
- **Remediation:** Add per-IP rate limit of ~100 lookups/minute. Consider adding a captcha or proof-of-work after threshold.
- **References:** https://owasp.org/API-Security/ - API Security Top 10 #4 (Lack of Resources & Rate Limiting)

---

## Finding: API-006

- **Title:** Email Alert Handler Exposes SMTP Password in Logs on Error
- **Severity:** Low
- **Confidence:** 70
- **File:** `internal/dashboard/dashboard.go:2231-2285`
- **Vulnerability Type:** CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)
- **Description:** The `handleAddEmail` handler accepts a `password` field for SMTP authentication:
  ```go
  Password string `json:"password"`
  ```
  While the response masks this field, the password is stored in `cfg.Alerting.Emails` and if an error occurs during save (e.g., JSON marshal error), the password could appear in error logs depending on how `sanitizeErr` processes the error. The `smtp_host`, `smtp_port`, `username`, and `password` are all stored in memory config.
- **Impact:** SMTP credentials could be exposed in server-side logs if serialization fails.
- **Remediation:** Never log the password field. Consider using a pointer to `*string` so nil vs empty can be distinguished, and never log non-nil passwords. Store only a hash/comparison value in memory config, not the plaintext.
- **References:** https://owasp.org/API-Security/ - API Security Top 10 #3 (Excessive Data Exposure)

---

## Finding: API-007

- **Title:** AI Endpoint URL Validation Uses net.ParseIP Which Fails on Domain Names
- **Severity:** Low
- **Confidence:** 70
- **File:** `internal/dashboard/ai_handlers.go:244-265`
- **Vulnerability Type:** CWE-20 (Improper Input Validation)
- **Description:** The `validateAIEndpointURL` function checks if hostname is an IP address and rejects private/loopback IPs:
  ```go
  ip := net.ParseIP(host)
  if ip != nil {
      if ip.IsLoopback() || ip.IsPrivate() || ...
  }
  ```
  If `net.ParseIP` returns nil (because it's a domain name, not an IP), the private IP checks are bypassed. An attacker could use DNS rebinding techniques or control a domain that resolves to a private IP. The HTTPS requirement and localhost string check provide some protection, but DNS rebinding is not fully mitigated.
- **Impact:** Potential SSRF via DNS rebinding against AI endpoint configuration.
- **Remediation:** Use `net.LookupIP` to resolve the domain before checking IP ranges, or implement DNS pinning with a TTL of 0. At minimum, add a warning comment that DNS rebinding protection is not complete.
- **References:** https://owasp.org/API-Security/ - API Security Top 10 #10 (Server-Side Request Forgery)

---

## Finding: API-008

- **Title:** AI Analyze Endpoint Loads All High-Score Events into Memory Without Limit
- **Severity:** Low
- **Confidence:** 75
- **File:** `internal/dashboard/ai_handlers.go:189-227`
- **Vulnerability Type:** CWE-400 (Uncontrolled Resource Consumption)
- **Description:** The `handleAIAnalyze` endpoint queries the event store with a limit, but if `eventStore.Query` returns all matching events despite the limit, or if the limit is manipulated, the entire event history with score >= 25 could be loaded:
  ```go
  evts, _, err := d.eventStore.Query(events.EventFilter{
      Limit:     n,  // n is from query param, capped at 1000
      MinScore:  25,
  })
  ```
  If the underlying event store has thousands of high-score events, this could cause memory pressure.
- **Impact:** Memory exhaustion from large event batches.
- **Remediation:** Enforce a hard limit of 100 events per AI analysis request regardless of the `limit` parameter. Add pagination/cursor support for AI analysis batch jobs.
- **References:** https://owasp.org/API-Security/ - API Security Top 10 #4 (Lack of Resources & Rate Limiting)

---

## Finding: API-009

- **Title:** Tenant Admin Endpoint Allows Unknown Fields Without Warning
- **Severity:** Low
- **Confidence:** 85
- **File:** `internal/dashboard/tenant_admin_handler.go:184-195`
- **Vulnerability Type:** CWE-136 (Type Errors) - partially applicable
- **Description:** The `handleUpdateTenant` function checks for unknown fields and rejects them:
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
  This is good, but other handlers like `handleAddEmail`, `handleAddWebhook`, and `handleAddRule` do not validate for unknown fields. Extra fields are silently ignored, which can lead to misconfiguration confusion.
- **Impact:** API clients may send outdated field names and get success responses with silently ignored fields, leading to misconfiguration.
- **Remediation:** Apply the same unknown-field validation pattern to all mutation handlers. Return a warning for unknown fields rather than silently ignoring them.
- **References:** https://owasp.org/API-Security/ - API Security Top 10 #9 (Improper Inventory Management)

---

## Finding: API-010

- **Title:** No Input Validation on DLP Pattern Test for ReDoS
- **Severity:** Low
- **Confidence:** 70
- **File:** `internal/dashboard/dlp_handlers.go:206-239`
- **Vulnerability Type:** CWE-1333 (Regular Expression Denial of Service)
- **Description:** The `handleTestPattern` endpoint accepts a user-provided regex pattern and test data:
  ```go
  var req struct {
      Pattern  string `json:"pattern"`
      TestData string `json:"test_data"`
  }
  result := dlpLayer.TestPattern(req.Pattern, req.TestData)
  ```
  If the underlying DLP layer uses a vulnerable regex engine or does not implement ReDoS protection, an attacker could submit a malicious regex that causes exponential backtracking.
- **Impact:** Potential denial of service via malicious regex patterns.
- **Remediation:** Implement regex timeout (e.g., 5 second limit) in the DLP layer. Use RE2 regex library which is guaranteed to terminate. Validate regex patterns for known dangerous constructs.
- **References:** https://owasp.org/API-Security/ - API Security Top 10 #10 (Injection)

---

## Positive Security Controls

The following practices are implemented well and should be preserved:

1. **CSRF Protection**: `verifySameOrigin()` properly validates Origin/Referer headers for state-changing requests authenticated via cookie (dashboard.go:76-106, 272-279)

2. **Session Security**: HMAC-signed session tokens with IP binding, concurrent session limits, server-side revocation (auth.go:74-141)

3. **SSRF Prevention**: Webhook URLs validated for private IP ranges (alerting/webhook.go:564-593), AI endpoint URLs validated (ai_handlers.go:244-265)

4. **Request Body Limits**: 1MB max via `limitedDecodeJSON()` (dashboard.go:1983-1993), 4KB for login form

5. **IP Address Validation**: GeoIP lookup validates IP format before lookup (dashboard.go:1713, 1742)

6. **Error Sanitization**: `sanitizeErr()` strips file paths and goroutine info (dashboard.go:2044-2064)

7. **Admin Key Separation**: System admin operations require separate `adminKey` via `isAdminAuthenticated()` (dashboard.go:124-134)

8. **Per-Tenant API Key Scoping**: Tenant API keys are scoped to tenant context via path prefix or header (auth.go:202-219)

9. **Login Rate Limiting**: 5 attempts per 5 minutes with 15-minute lockout (dashboard.go:100-103)

10. **Content-Type Validation**: `handleGeoIPLookupPost` requires `application/json` (dashboard.go:1728-1730)

11. **Field Allowlisting in Tenant Updates**: `handleUpdateTenant` validates allowed field names (tenant_admin_handler.go:184-195)

12. **Security Headers**: `SecurityHeadersMiddleware` sets comprehensive CSP, HSTS, X-Frame-Options, etc. (middleware.go:54-74)

---

## Summary

| Finding | Severity | Confidence | Category |
|---------|----------|------------|----------|
| API-001: Debug pprof endpoints | High | 95 | Information Disclosure |
| API-002: No rate limiting on API | Medium | 90 | Resource Exhaustion |
| API-003: Offset enumeration | Medium | 85 | Data Enumeration |
| API-004: Weak tenant API key hash | Medium | 75 | Cryptographic Weakness |
| API-005: GeoIP lookup no rate limit | Low | 80 | Resource Exhaustion |
| API-006: SMTP password in logs | Low | 70 | Information Disclosure |
| API-007: AI URL DNS rebinding | Low | 70 | SSRF |
| API-008: AI analyze memory | Low | 75 | Resource Exhaustion |
| API-009: Unknown fields silent | Low | 85 | Input Validation |
| API-010: DLP ReDoS risk | Low | 70 | DoS |

**Critical: 0 | High: 1 | Medium: 3 | Low: 6**

The dashboard API is generally well-secured with proper authentication, CSRF protection, SSRF prevention, and input validation. The primary concerns are the exposure of pprof endpoints behind standard auth and the lack of rate limiting on most API endpoints.
