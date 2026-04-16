# sc-lang-go Results

## Findings

### [INFO] math/rand Usage in Attack Simulation Tool

- **File:** scripts/attack-simulation/main.go:12
- **CWE:** CWE-338 (Use of Predictable Pseudorandom Number Generator)
- **Confidence:** 100%
- **Description:** The attack simulation script uses `math/rand` for generating test traffic. This is acceptable for load testing purposes and does not affect the GuardianWAF itself.
- **Exploit Scenario:** N/A - This is a testing tool, not production code.
- **Remediation:** No action required. If cryptographic randomness is needed for security-sensitive operations, use `crypto/rand`.

---

### [INFO] sync.Map Usage in Rate Limiting and Caching

- **File:** internal/layers/ratelimit/ratelimit.go:37-38, internal/layers/apisecurity/jwt.go:49, internal/layers/apisecurity/jwt.go:71, internal/alerting/webhook.go:67, internal/dashboard/auth.go:35-42
- **CWE:** CWE-362 (Race Condition)
- **Confidence:** 95%
- **Description:** Multiple sync.Map instances are used for rate limit buckets, JWT JWKS cache, alerting last-fire tracking, and session management. Go's sync.Map is safe for concurrent use and appropriate for these "append-mostly" workloads as documented in the ADR-0029.
- **Exploit Scenario:** sync.Map is designed for concurrent access; it is safe and optimized for high-read, low-write scenarios.
- **Remediation:** No action required. This is an intentional design choice documented in ADR-0029.

---

### [INFO] Panic Recovery in Pipeline

- **File:** internal/engine/pipeline.go:73-77
- **CWE:** CWE-248 (Unchecked Exception)
- **Confidence:** 100%
- **Description:** The pipeline Execute function includes panic recovery to prevent a single layer panic from crashing the entire request processing. The panic is re-raised after cleanup (returning the timing map to the pool).
- **Exploit Scenario:** A panic in any security layer is caught, logged, and the request is allowed to pass. This prevents DoS via panic-inducing requests but may allow malicious requests through if a detector panics.
- **Remediation:** This is a deliberate trade-off to maintain availability. Ensure all layer code is thoroughly tested to prevent unexpected panics.

---

### [MEDIUM] Intentional Panic on Crypto/Rand Failure in Bot Detection

- **File:** internal/layers/botdetect/collector_handler.go:386-393
- **CWE:** CWE-248 (Unchecked Exception)
- **Confidence:** 100%
- **Description:** The challenge HMAC key initialization uses a panic if `crypto/rand` fails: `panic("guardianwaf: crypto/rand failed — cannot generate secure challenge HMAC key: " + err.Error())`. This is intentional because a WAF must not operate with a predictable HMAC key.
- **Exploit Scenario:** If the system entropy is exhausted (extremely rare), the WAF will panic and stop accepting requests rather than operating insecurely.
- **Remediation:** No action required. This is a deliberate security decision - a WAF with predictable HMAC keys would be fundamentally broken.

---

### [INFO] JWT Default Algorithm Restriction

- **File:** internal/layers/apisecurity/jwt.go:232-241
- **CWE:** CWE-345 (Insufficient Verification of Data Authenticity)
- **Confidence:** 90%
- **Description:** When JWT `algorithms` config is not explicitly set, only RS256 and ES256 are allowed by default. A warning is logged at startup. Other legitimate algorithms like ES512 or PS256 would be silently rejected.
- **Exploit Scenario:** Operators may not notice the startup warning and deploy with tokens that use non-default algorithms, causing authentication failures.
- **Remediation:** Explicitly set the `algorithms` field in JWT configuration to include all intended algorithms.

---

### [PASS] JWT Algorithm "none" Rejection

- **File:** internal/layers/apisecurity/jwt.go:217-218
- **CWE:** CWE-347 (Improper Verification of Cryptographic Signature)
- **Confidence:** 100%
- **Description:** The `isAlgorithmAllowed` function explicitly returns `false` for `alg == ""` and `alg == "none"`. Tokens signed with algorithm "none" cannot be forged.
- **Exploit Scenario:** N/A - Control is secure.
- **Remediation:** None required.

---

### [PASS] JWT Algorithm Confusion Protection

- **File:** internal/layers/apisecurity/jwt.go:220-230
- **CWE:** CWE-347 (Improper Verification of Cryptographic Signature)
- **Confidence:** 100%
- **Description:** If an asymmetric key source is configured (PEM, key file, or JWKS URL), HMAC algorithms (HS256/HS384/HS512) are blocked. This prevents the RS256-to-HS256 algorithm confusion attack.
- **Exploit Scenario:** N/A - Control is secure.
- **Remediation:** None required.

---

### [PASS] JWT JWKS URL SSRF Protection

- **File:** internal/layers/apisecurity/jwt.go:1073-1111
- **CWE:** CWE-918 (Server-Side Request Forgery)
- **Confidence:** 100%
- **Description:** The `validateJWKSURL` function rejects localhost, .internal, .local domains, and private/loopback/link-local IP addresses before JWKS fetching.
- **Exploit Scenario:** N/A - Control is secure.
- **Remediation:** None required.

---

### [PASS] WebSocket Origin Validation

- **File:** internal/layers/websocket/websocket.go:187-193, 226-269
- **CWE:** CWE-346 (Origin Validation Error)
- **Confidence:** 100%
- **Description:** Origin header is validated against an allowlist with support for wildcard subdomains (*.example.com). When no origins are configured, same-origin policy is enforced (cross-origin requests rejected).
- **Exploit Scenario:** N/A - Control is secure.
- **Remediation:** None required.

---

### [PASS] Cookie Security Attributes

- **File:** internal/layers/challenge/challenge.go:153-161, internal/dashboard/auth.go:290-296, internal/dashboard/dashboard.go:438-445, internal/layers/botdetect/collector_handler.go:274-281
- **CWE:** CWE-614 (Sensitive Cookie Without 'HttpOnly' Flag)
- **Confidence:** 100%
- **Description:** Challenge cookies use `HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode`. Dashboard session cookies use `SameSiteStrictMode`. All security-relevant cookies have appropriate attributes.
- **Exploit Scenario:** N/A - Control is secure.
- **Remediation:** None required.

---

### [PASS] GraphQL Security Controls

- **File:** internal/layers/graphql/parser.go:133-140, internal/layers/graphql/layer.go:36-58
- **CWE:** CWE-400 (Uncontrolled Resource Consumption)
- **Confidence:** 100%
- **Description:** GraphQL layer implements: max parse depth of 256, max query length of 256KB, max depth limiting, max complexity limiting, introspection blocking by default, batch size limiting, and directive injection detection.
- **Exploit Scenario:** N/A - Control is secure.
- **Remediation:** None required.

---

### [PASS] SSRF Protection

- **File:** internal/proxy/target.go:29-65, internal/ai/client.go:58, internal/alerting/webhook.go:586-602, internal/layers/siem/exporter.go:376-391, internal/layers/apisecurity/jwt.go:1089-1111
- **CWE:** CWE-918 (Server-Side Request Forgery)
- **Confidence:** 100%
- **Description:** Multiple `IsPrivateOrReservedIP` checks prevent requests to private, loopback, link-local, and unspecified IP addresses. Used consistently for upstream proxy, AI client, webhooks, SIEM exporter, and JWT JWKS fetching.
- **Exploit Scenario:** N/A - Control is secure.
- **Remediation:** None required.

---

### [PASS] HTTP Server Timeouts Configured

- **File:** cmd/guardianwaf/main.go:994-996, cmd/guardianwaf/main.go:1088-1091, cmd/guardianwaf/main.go:1751-1753
- **CWE:** CWE-400 (Uncontrolled Resource Consumption)
- **Confidence:** 100%
- **Description:** All HTTP servers set ReadTimeout (30s), WriteTimeout (30s), IdleTimeout (120s), and ReadHeaderTimeout (10s).
- **Exploit Scenario:** N/A - Control is secure.
- **Remediation:** None required.

---

### [PASS] Path Traversal Prevention in Pipeline

- **File:** internal/engine/pipeline.go:89-96
- **CWE:** CWE-22 (Path Traversal)
- **Confidence:** 100%
- **Description:** The pipeline uses `path.Clean(ctx.Path)` before checking exclusions to prevent bypass via sequences like `/api/webhook/../../admin`.
- **Exploit Scenario:** N/A - Control is secure.
- **Remediation:** None required.

---

### [PASS] Open Redirect Prevention

- **File:** cmd/guardianwaf/main.go:1050-1076
- **CWE:** CWE-601 (URL Redirection to Untrusted Site)
- **Confidence:** 100%
- **Description:** Host header is validated against virtual host domains (with wildcard support) before use in redirects. Protocol-relative URLs (//evil.com) are stripped.
- **Exploit Scenario:** N/A - Control is secure.
- **Remediation:** None required.

---

### [PASS] HTML Escaping in Error Pages

- **File:** internal/layers/response/errorpage.go:133-139
- **CWE:** CWE-79 (Cross-site Scripting)
- **Confidence:** 100%
- **Description:** The `escapeHTML` function properly escapes `&`, `<`, `>`, `"`, and `'` characters in error page content.
- **Exploit Scenario:** N/A - Control is secure.
- **Remediation:** None required.

---

### [PASS] CRS Regex Timeout Protection

- **File:** internal/layers/crs/operators.go:23-52
- **CWE:** CWE-1333 (Regular Expression Denial of Service)
- **Confidence:** 100%
- **Description:** Go's regexp uses RE2 (linear-time, no catastrophic backtracking). Additionally, a 5-second timeout (`regexExecutionTimeout`) is applied via `matchWithTimeout` for defense-in-depth.
- **Exploit Scenario:** N/A - Control is secure.
- **Remediation:** None required.

---

### [PASS] JSON Deserialization with Error Handling

- **File:** internal/layers/graphql/layer.go:422-430, internal/ai/provider.go:246, internal/cluster/cluster.go:948-975
- **CWE:** CWE-502 (Deserialization of Untrusted Data)
- **Confidence:** 100%
- **Description:** All `json.Unmarshal` calls check errors before using the data. No use of `encoding/gob` or other unsafe deserialization.
- **Exploit Scenario:** N/A - Control is secure.
- **Remediation:** None required.

---

### [PASS] No text/template Usage

- **File:** N/A
- **CWE:** CWE-79 (Cross-site Scripting)
- **Confidence:** 100%
- **Description:** No usage of `text/template` (which does not auto-escape) found in the codebase. All template rendering uses `html/template` or manual string building with escaping.
- **Exploit Scenario:** N/A - Control is secure.
- **Remediation:** None required.

---

### [PASS] No unsafe.Pointer Usage

- **File:** N/A
- **CWE:** CWE-787 (Out-of-bounds Write)
- **Confidence:** 100%
- **Description:** No usage of `unsafe.Pointer` found in the codebase. All memory operations use safe Go patterns.
- **Exploit Scenario:** N/A - Control is secure.
- **Remediation:** None required.

---

### [INFO] Docker Discovery exec.Command Usage

- **File:** internal/docker/client.go:270, internal/docker/client.go:321
- **CWE:** CWE-78 (OS Command Injection)
- **Confidence:** 80%
- **Description:** The Docker client uses `exec.CommandContext(ctx, "docker", args...)` where `args` are constructed from Docker API responses (container events, label parsing). While the args are internally generated, an attacker who could manipulate Docker labels or container names could potentially inject arguments.
- **Exploit Scenario:** If an attacker can modify Docker container labels (e.g., via another service), they could influence the args passed to docker CLI commands.
- **Remediation:** Consider validating Docker label values to ensure they don't contain shell metacharacters before including them in command arguments.

---

## Summary

| Category | Finding | Severity |
|----------|---------|----------|
| JWT | Algorithm "none" rejection | PASS |
| JWT | Algorithm confusion protection | PASS |
| JWT | JWKS SSRF protection | PASS |
| JWT | Default algorithm restriction | MEDIUM (info) |
| WebSocket | Origin validation | PASS |
| Cookies | Security attributes | PASS |
| GraphQL | Query depth/complexity limits | PASS |
| SSRF | Private IP detection | PASS |
| HTTP | Server timeouts | PASS |
| Path Traversal | Path cleaning | PASS |
| Open Redirect | Host header validation | PASS |
| XSS | HTML escaping | PASS |
| ReDoS | CRS regex timeout | PASS |
| Deserialization | JSON error handling | PASS |
| Templates | No text/template | PASS |
| Memory | No unsafe.Pointer | PASS |
| Panic Handling | Pipeline recovery | INFO |
| Crypto | Panic on entropy failure | INFO (by design) |
| math/rand | Attack simulation tool | INFO (acceptable) |
| Command Injection | Docker client args | INFO (low risk) |

---

## Follow-up Verification (2026-04-16)

### 1. ipacl.go:172 - autoBanEntry.Count Race Condition

**Finding:** NOT A VULNERABILITY (False positive)

**Analysis:**
- Line 30 comment: `Count int // protected by Layer.mu`
- `AddAutoBan()` (lines 162-187) holds `l.mu.Lock()` before `entry.Count++` (line 172)
- All accesses to `autoBan` map protected by `l.mu` RWMutex
- `ExpiresAt` uses `atomic.Value` for lock-free reads; `Count` protected by mutex
- **Conclusion:** Properly synchronized. No race condition.

---

### 2. engine/context.go - sync.Pool ReleaseContext() Field Reset

**Finding:** SECURE - No cross-request contamination risk

**Analysis:**
- `ReleaseContext()` (lines 247-293) resets ALL fields to zero values:
  - `Request`, `ClientIP`, `QueryParams`, `Headers`, `Cookies`, `Body`, `NormalizedQuery`, `NormalizedHeaders`, `Accumulator`, `Metadata` → `nil`
  - String fields → `""`, int/uint fields → `0`, bool → `false`
  - JA4 TLS fingerprinting fields explicitly cleared (lines 281-288)
- Returns context to pool via `contextPool.Put(ctx)`
- **Conclusion:** Properly implemented. No cross-request leakage.

---

### 3. response/errorpage.go - escapeHTML() Function

**Finding:** SECURE - Correct and complete

**Analysis:**
- Function (lines 133-140) escapes five critical HTML metacharacters:
  - `&` → `&amp;`, `<` → `&lt;`, `>` → `&gt;`, `"` → `&quot;`, `'` → `&#39;`
- Uses `strings.ReplaceAll` correctly
- Applied in both production and development error pages
- **Conclusion:** XSS prevention is correct.

---

### 4. config/config.go - YAML Unsafe Tags (!<!>)

**Finding:** SECURE - No unsafe yaml tags

**Analysis:**
- Line 3 comment: "The yaml struct tags are documentary — actual loading uses the YAML parser's Node tree"
- No `!!python/object`, `!<!>`, or other unsafe tags present
- Custom Node tree-based YAML parser used for actual loading (not yaml.Unmarshal)
- **Conclusion:** No YAML deserialization vulnerability.

---

### 5. docker/client.go - isSafeContainerRef() Function

**Finding:** SECURE - Properly implemented

**Analysis:**
- Allowlist validation: permits `0-9`, `a-z`, `A-Z`, `-`, `_`, `.` only
- Length check: `0 < len(id) <= 128`
- Rejects all shell metacharacters: `|`, `;`, `$`, `&`, `<`, `>`, `` ` ``, `!`, `*`, `?`, etc.
- Used in `ListContainers()` (line 166) and `InspectContainer()` (line 226)
- Prevents command injection in `docker inspect <id>` calls
- **Conclusion:** Command injection prevented.

---

### 6. apisecurity/apikey.go - Constant-Time Comparison

**Finding:** SECURE - Implemented correctly

**Analysis:**
- Uses `crypto/subtle.ConstantTimeCompare()` at line 115
- Hash format fixed: `"sha256:"` (8 chars) + 64 hex = 72 bytes total
- Map iteration (lines 113-117) is acceptable; Go randomizes map iteration order
- **Conclusion:** Timing-safe comparison for API key validation.

---

## Follow-up Summary

| Check | Status | Notes |
|-------|--------|-------|
| IPACL Count race | FALSE POSITIVE | Protected by mutex |
| Context ReleaseContext() | SECURE | All fields reset |
| escapeHTML() | SECURE | Complete entity encoding |
| YAML unsafe tags | SECURE | Documentary only |
| isSafeContainerRef() | SECURE | Allowlist validation |
| ConstantTimeCompare | SECURE | Correct crypto/subtle usage |

**Verified Issues:** 0 | **False Positives Cleared:** 1 (IPACL Count)
