# Security Check — Verified Findings

**Project:** GuardianWAF
**Scan Date:** 2026-04-16
**Phase 3 Verification Results**

---

## Summary

| Severity | Count |
|----------|-------|
| Critical | 4 |
| High | 27 |
| Medium | 42 |
| Low | 17 |
| **Total** | **90** |

Eliminated as false positives: ~28 findings (see Eliminated section)

---

## Critical Findings (4)

### VULN-001: WebSocket Origin Validation Bypass in Default Configuration
- **Severity:** Critical
- **Confidence:** 90%
- **CWE:** CWE-1385 (Missing Origin Validation in WebSocket)
- **File:** `internal/layers/websocket/websocket.go:187-193`
- **Description:** The `ValidateHandshake` function checks `if len(s.config.AllowedOrigins) > 0` before performing origin validation. When `AllowedOrigins` is empty (the default), NO origin check is performed — the entire validation block is skipped. The `isAllowedOrigin` function (lines 224-269) has correct same-origin logic but is **dead code in the default configuration**. This allows any cross-origin WebSocket connection by default.
- **Exploit Scenario:** Attacker hosts a malicious page that initiates a WebSocket connection to the WAF's WebSocket endpoint, bypassing origin checks entirely.
- **Remediation:**
  ```go
  // Fix: always check origin, use same-origin policy when AllowedOrigins is empty
  if !s.isAllowedOrigin(origin, r) {
      return fmt.Errorf("origin not allowed: %s", origin)
  }
  ```
- **Reference:** `internal/layers/websocket/websocket.go:224-236`

---

### VULN-002: Rate Limit Bucket Exhaustion Bypass
- **Severity:** Critical
- **Confidence:** 75%
- **CWE:** CWE-770 (Allocation of Resources Without Limits)
- **File:** `internal/layers/ratelimit/ratelimit.go:148-149`
- **Description:** The `getOrCreateBucket()` function returns `nil` when `bucketCount >= maxBuckets` (500,000). When this happens, `bucket.Allow()` is never called — the rate limit check is silently **skipped entirely**. An attacker with many IPs (or a botnet) can exhaust the bucket limit and bypass rate limiting for all subsequent requests.
- **Exploit Scenario:** Attacker sends requests from 500,000+ distinct IPs to fill the bucket map. After the cap is reached, every subsequent request bypasses rate limiting.
- **Remediation:** When bucket limit is reached, reject the request (return block) instead of silently skipping.
- **Reference:** `internal/layers/ratelimit/ratelimit.go:37-38, 148-149`

---

### VULN-003: Cluster Auth Secret Transmitted in Cleartext Over HTTP
- **Severity:** Critical
- **Confidence:** 90%
- **CWE:** CWE-319 (Cleartext Transmission of Sensitive Data)
- **File:** `internal/cluster/cluster.go:491-495, 813-814`
- **Description:** When `AuthSecret` is configured but TLS is not enabled, the cluster authentication secret is transmitted in cleartext via the `X-Cluster-Auth` header in every inter-node HTTP request. A network eavesdropper can capture the secret and authenticate to other cluster nodes.
- **Exploit Scenario:** Network attacker captures `X-Cluster-Auth` header value, uses it to join cluster as a rogue node, receives full WAF configuration including per-tenant rules and API keys.
- **Remediation:** Require TLS (`tls_cert_file` + `tls_key_file`) when `AuthSecret` is configured. The existing warning at line 813-814 logs a warning but does NOT prevent transmission.
- **Reference:** `internal/cluster/cluster.go:491-495`

---

### VULN-004: Debug pprof Endpoints Exposed Behind Standard API Authentication
- **Severity:** Critical
- **Confidence:** 85%
- **CWE:** CWE-200 (Exposure of Sensitive Information)
- **File:** `internal/dashboard/dashboard.go:217-222`
- **Description:** The `pprof` endpoints (`/debug/pprof/*`) are registered behind `authWrap()` which only requires the standard API key. These endpoints expose sensitive runtime data: goroutine stacks with local variables (Cmdline, Profile, Symbol, Trace), memory contents (Heap profile), and internal application state. Attackers with a valid API key can harvest this data for attack planning.
- **Exploit Scenario:** Attacker with valid API key accesses `/debug/pprof/heap` to find internal variable values, or `/debug/pprof/goroutine?debug=1` to map internal code structure.
- **Remediation:** Require a separate high-privilege key or disable pprof entirely in production. Add a separate `pprofAuthWrap` that requires additional authentication.
- **Reference:** `internal/dashboard/dashboard.go:217-222`

---

## High Findings (27)

### VULN-005: No Rate Limiting on Authentication Endpoints
- **Severity:** High | **Confidence:** 90% | **CWE:** CWE-307
- **File:** `internal/layers/ratelimit/ratelimit.go:16-25`
- Only `ip` and `ip+path` scopes are supported. No per-user/session rate limiting exists. ATO layer provides brute force protection but is separate from rate limiting.
- **Remediation:** Add `user` or `session` scope using `ctx.SessionID` as bucket key.

### VULN-006: CI/CD — GitHub Actions Not Pinned to Commit SHAs
- **Severity:** High | **Confidence:** 100% | **CWE:** CWE-829
- **File:** `.github/workflows/ci.yml`, `release.yml`, `website.yml`
- All third-party actions use tag references (`@v4`) instead of `@sha`. Compromised action can steal secrets or modify builds.
- **Remediation:** Pin all third-party actions to full SHA commits.

### VULN-007: CI/CD — No SAST Scanning in Pipeline
- **Severity:** High | **Confidence:** 90% | **CWE:** CWE-1194
- No CodeQL, Semgrep, or Gosec integration. Security vulnerabilities can be merged without detection.
- **Remediation:** Integrate `golangci-lint` or `gosec` in CI, fail on findings.

### VULN-008: CI/CD — No Container Vulnerability Scanning
- **Severity:** High | **Confidence:** 90% | **CWE:** CWE-1194
- Docker images are built and pushed to GHCR with no Trivy/Snyk scan for CVEs.
- **Remediation:** Add Trivy image scanning in CI before push.

### VULN-009: CI/CD — No Secret Scanning
- **Severity:** High | **Confidence:** 85% | **CWE:** CWE-200
- No TruffleHog or GitHub Advanced Security to catch accidentally committed credentials.
- **Remediation:** Add `trufflehog` or enable GitHub Advanced Security secret scanning.

### VULN-010: CI/CD — No Go Dependency Vulnerability Scanning
- **Severity:** High | **Confidence:** 85% | **CWE:** CWE-1194
- `govulncheck` is not integrated. Known Go CVEs could be deployed.
- **Remediation:** Add `govulncheck ./...` in CI.

### VULN-011: Docker — docker-compose.test.yml Runs as Root
- **Severity:** High | **Confidence:** 100% | **CWE:** CWE-250
- **File:** `docker-compose.test.yml`
- Both `guardianwaf` and `backend` services run as root. Container escape risk if compromised.
- **Remediation:** Create a `guardianwaf` user and run as that user.

### VULN-012: Docker — docker-compose.yml Missing Security Hardening
- **Severity:** High | **Confidence:** 100% | **CWE:** CWE-250
- **File:** `docker-compose.yml`
- Missing `security_opt`, `cap_drop: ALL`, `read_only: true`. Service can escalate privileges.
- **Remediation:** Add security options per Docker security checklist.

### VULN-013: Docker — Mutable `latest` Tag in Production Compose
- **Severity:** High | **Confidence:** 100% | **CWE:** CWE-829
- **File:** `docker-compose.yml`, `examples/sidecar/docker-compose.yml`
- Using `latest` tag means image is not pinned. Updates could introduce vulnerabilities.
- **Remediation:** Pin to specific version tags.

### VULN-014: Docker — Missing Memory/CPU Resource Limits
- **Severity:** High | **Confidence:** 100% | **CWE:** CWE-400
- **File:** `docker-compose.yml`
- No resource limits on services. A single service can exhaust all host memory.
- **Remediation:** Add `mem_limit`, `cpu_shares` to all services.

### VULN-015: IaC — Container Images Use `latest` Tag
- **Severity:** High | **Confidence:** 100% | **CWE:** CWE-829
- **File:** `examples/kubernetes/configmap.yaml`, `contrib/k8s/deployment.yaml`
- `image: guardianwaf/guardianwaf:latest` is not pinned. Same as VULN-013.
- **Remediation:** Pin to versioned release tags.

### VULN-016: IaC — TLS Disabled in contrib/k8s ConfigMap
- **Severity:** High | **Confidence:** 100% | **CWE:** CWE-319
- **File:** `contrib/k8s/configmap.yaml`
- WAF configmap has `tls_enabled: false`. Production WAFs must use TLS.
- **Remediation:** Set `tls_enabled: true` and provide cert manager integration.

### VULN-017: IaC — GitHub Actions Unpinned SHAs
- **Severity:** High | **Confidence:** 100% | **CWE:** CWE-829
- Same as VULN-006.
- **Remediation:** Same as VULN-006.

### VULN-018: JWT — JWKS SSRF Validation Only at Init, Not on Refresh
- **Severity:** High | **Confidence:** 85% | **CWE:** CWE-918
- **File:** `internal/layers/apisecurity/jwt.go:237-280`
- `validateJWKSURL()` runs at startup only. `fetchJWKS()` on 5-minute refresh does NOT re-validate. DNS rebinding can serve malicious keys.
- **Remediation:** Re-validate URL in `fetchJWKS()` before each fetch.

### VULN-019: SSRF — AI Client Only Warns on Private IPs, Doesn't Block
- **Severity:** High | **Confidence:** 80% | **CWE:** CWE-918
- **File:** `internal/ai/client.go:55-63`
- `validateURLNotPrivate()` logs a warning but does NOT block the request when private IPs are detected. Attacker-controlled AI endpoint config allows SSRF.
- **Remediation:** Return error and block when private/reserved IPs are detected.

### VULN-020: API — Offset-Based Event Pagination Allows Enumeration
- **Severity:** High | **Confidence:** 75% | **CWE:** CWE-200
- **File:** `internal/dashboard/dashboard_handlers.go`
- Events API uses `?offset=N` without authorization check on offset ranges. All events across all tenants may be enumerable via iteration.
- **Remediation:** Validate offset against authorized tenant boundaries.

### VULN-021: API — Legacy Per-Tenant API Key Uses Unsalted SHA256
- **Severity:** High | **Confidence:** 75% | **CWE:** CWE-328
- **File:** `internal/layers/apisecurity/apikey.go`
- API key hashes use fast SHA256 with no salt. Rainbow table attack feasible if hash database is leaked.
- **Remediation:** Use bcrypt/argon2 with per-key salt.

### VULN-022: Rate Limiting — Violations sync.Map Has No Cleanup
- **Severity:** High | **Confidence:** 85% | **CWE:** CWE-400
- **File:** `internal/layers/ratelimit/ratelimit.go`
- `violations` sync.Map has no expiration or hard cap. Sustained multi-IP attack can cause memory exhaustion.
- **Remediation:** Add `CleanupExpired()` for violations, similar to bucket cleanup.

### VULN-023: Rate Limiting — Auto-Ban Counter Never Decrements
- **Severity:** High | **Confidence:** 90% | **CWE:** CWE-840
- **File:** `internal/layers/ratelimit/ratelimit.go:274-293`
- `trackViolation()` increments but auto-ban entries are only removed on expiry. Permanent ban entries accumulate indefinitely.
- **Remediation:** Add periodic cleanup of resolved ban entries.

### VULN-024: Business Logic — Impossible Travel Bypass via Small Distances
- **Severity:** High | **Confidence:** 65% | **CWE:** CWE-840
- **File:** `internal/layers/ato/ato.go`
- ATO impossible travel check uses fixed thresholds. Small geographic movements within threshold time could bypass detection.
- **Remediation:** Add ML-based anomaly detection for travel patterns.

### VULN-025: Business Logic — ATO Brute Force Per-Email Counter Issues
- **Severity:** High | **Confidence:** 60% | **CWE:** CWE-307
- **File:** `internal/layers/ato/ato.go`
- Per-email counter reset on password change may allow unlimited attempts after credential rotation.
- **Remediation:** Preserve attempt history across password changes.

### VULN-026: Business Logic — Tenant Resolution Header-Based Impersonation
- **Severity:** High | **Confidence:** 75% | **CWE:** CWE-840
- **File:** `internal/tenant/middleware.go:335-359`
- Header-based tenant resolution (`X-Tenant-ID`) bypasses domain-based routing. Compromised API key could impersonate any tenant.
- **Remediation:** Require additional validation for header-based tenant resolution.

### VULN-027: WebSocket — Hardcoded 2MB Frame Size Inconsistent with 1MB Default
- **Severity:** High | **Confidence:** 85% | **CWE:** CWE-400
- **File:** `internal/layers/websocket/websocket.go:539`
- `ParseFrame` hardcodes `maxFramePayload = 2MB` while `MaxFrameSize` config defaults to 1MB. Inconsistent validation.
- **Remediation:** Use `s.config.MaxFrameSize` in `ParseFrame`.

### VULN-028: CI/CD — Release Workflow Broad Write Permissions at Workflow Level
- **Severity:** High | **Confidence:** 80% | **CWE:** CWE-284
- **File:** `.github/workflows/release.yml`
- `permissions: contents: write, packages: write` set at workflow level instead of job level. Overpermissioned if workflow is forked.
- **Remediation:** Scope permissions per job, least privilege principle.

### VULN-029: IaC — Missing Resource Limits in Kubernetes
- **Severity:** High | **Confidence:** 85% | **CWE:** CWE-400
- **File:** All Kubernetes deployment manifests
- `contrib/k8s/deployment.yaml` has no `resources.requests`/`resources.limits`. Pods can consume unlimited CPU/memory.
- **Remediation:** Add resource requests and limits to all containers.

---

## Medium Findings (42)

### VULN-030: JWT Default Algorithm Whitelist Restricts RS256/ES256 Only
- **Severity:** Medium | **Confidence:** 90% | **CWE:** CWE-327
- **File:** `internal/layers/apisecurity/jwt.go`
- If no algorithms configured, defaults to RS256/ES256. Operators may miss the warning and assume all algorithms work.

### VULN-031: JWKS DNS Rebinding TOCTOU (Same as VULN-018)
- **Severity:** Medium | **Confidence:** 75% | **CWE:** CWE-918
- See VULN-018.

### VULN-032: AI Catalog URL DNS Rebinding
- **Severity:** Medium | **Confidence:** 70% | **CWE:** CWE-918
- **File:** `internal/ai/provider.go`
- `FetchCatalog()` validates URL at setup but uses plain `http.Client` at fetch time. DNS re-resolved without re-validation.

### VULN-033: CORS — Wildcard Origin Default Config
- **Severity:** Medium | **Confidence:** 90% | **CWE:** CWE-942
- **File:** `guardianwaf.yaml` default config
- `allowed_origins: ["*"]` with `allow_credentials: false` is Mitigated. Risk if credentials enabled.

### VULN-034: CORS — Missing `Vary: Origin` Header
- **Severity:** Medium | **Confidence:** 85% | **CWE:** CWE-291
- **File:** `internal/engine/engine.go:423-441`
- `applyCORSHook` does not set `Vary: Origin`. Caching proxies may serve wrong origin responses.

### VULN-035: Session — Missing Pre-Login Session Invalidation (Fixation)
- **Severity:** Medium | **Confidence:** 80% | **CWE:** CWE-384
- **File:** `internal/dashboard/dashboard.go:332`
- Login does not invalidate pre-existing session. Session fixation theoretically possible.

### VULN-036: Security Headers — CSP Missing `frame-ancestors`
- **Severity:** Medium | **Confidence:** 85% | **CWE:** CWE-1021
- **File:** `internal/layers/response/headers.go:25`
- Default CSP lacks `frame-ancestors` directive. Clickjacking protection incomplete.

### VULN-037: Security Headers — Response Layer Defaults to SAMEORIGIN
- **Severity:** Medium | **Confidence:** 80% | **CWE:** CWE-1021
- **File:** `internal/layers/response/headers.go:25`
- `X-Frame-Options: SAMEORIGIN` should be `DENY` for maximum clickjacking protection.

### VULN-038: File Upload — Extension Validation Without Magic Bytes
- **Severity:** Medium | **Confidence:** 80% | **CWE:** CWE-434
- **File:** `internal/layers/dlp/layer.go:462-518`
- DLP scanner blocks by extension only. Polyglot files or alternate data streams could bypass.

### VULN-039: Path Traversal — `handleDistAssets` Uses Strings.Contains
- **Severity:** Medium | **Confidence:** 75% | **CWE:** CWE-22
- **File:** `internal/dashboard/dashboard.go:1835-1843`
- Uses `strings.Contains(cleanPath, "..")` instead of canonicalization. Mitigated by `embed.FS`.

### VULN-040: Race Condition — GeoIP File TOCTOU
- **Severity:** Medium | **Confidence:** 80% | **CWE:** CWE-362
- **File:** `internal/geoip/geoip.go:236-240`
- `os.Stat` check before `LoadCSV` — file could be swapped between check and use.

### VULN-041: Race Condition — TLS Certificate Hot-Reload TOCTOU
- **Severity:** Medium | **Confidence:** 75% | **CWE:** CWE-362
- **File:** `internal/tls/certstore.go:217-231`
- `os.Stat` then `LoadX509KeyPair` — file swap between check and reload possible.

### VULN-042: Rate Limiting — No Per-User/Session Scope
- **Severity:** Medium | **Confidence:** 80% | **CWE:** CWE-307
- **File:** `internal/layers/ratelimit/ratelimit.go`
- After auth, no per-user rate limiting exists. Authenticated account attacks possible.

### VULN-043: Auth — Static API Key with No MFA
- **Severity:** Medium | **Confidence:** 85% | **CWE:** CWE-308
- **File:** `internal/dashboard/auth.go`
- Dashboard uses single static API key. No multi-factor authentication available.

### VULN-044: Auth — API Key Hash Uses Fast SHA256
- **Severity:** Medium | **Confidence:** 80% | **CWE:** CWE-328
- **File:** `internal/layers/apisecurity/apikey.go`
- SHA256 is fast. If hashes are leaked, brute force is feasible. Use bcrypt/argon2.

### VULN-045: Auth — Login Rate Limiting Per-Node Only
- **Severity:** Medium | **Confidence:** 80% | **CWE:** CWE-307
- **File:** `internal/dashboard/dashboard.go`
- Login rate limiting is per-node, not distributed. Distributed attack can bypass by hitting different nodes.

### VULN-046: JWT — Ed25519 Limited to Raw 32-byte Keys
- **Severity:** Medium | **Confidence:** 70% | **CWE:** CWE-347
- **File:** `internal/layers/apisecurity/jwt.go`
- Standard PKIX DER format Ed25519 keys fail to load. JWKS-sourced Ed25519 unusable.

### VULN-047: Open Redirect — HTTP-to-HTTPS Redirect Query Param Edge Case
- **Severity:** Medium | **Confidence:** 70% | **CWE:** CWE-601
- **File:** `cmd/guardianwaf/main.go`
- `redirect=?` query param checked for `//` prefix but not `//` embedded in value.

### VULN-048: DLP — AI Analyze Endpoint Loads Unbounded Events
- **Severity:** Medium | **Confidence:** 75% | **CWE:** CWE-400
- **File:** `internal/dashboard/ai_handlers.go`
- `handleAIAnalyze` loads all matching events into memory. Large result sets can cause OOM.

### VULN-049: Rate Limiting — TOCTOU Between Bucket Count Check and LoadOrStore
- **Severity:** Medium | **Confidence:** 75% | **CWE:** CWE-362
- **File:** `internal/layers/ratelimit/ratelimit.go:37-38`
- Transient cap exceedance possible under extreme concurrency.

### VULN-050: Clientside CSP Hook Never Applied
- **Severity:** Medium | **Confidence:** 85% | **CWE:** CWE-1021
- **File:** `internal/layers/clientside/layer.go:92`, `internal/engine/engine.go:410-420`
- `clientside_csp_hook` registered but never called by `applyResponseHook`.

### VULN-051: CI/CD — No Concurrency Controls on CI Workflow
- **Severity:** Medium | **Confidence:** 75% | **CWE:** CWE-362
- **File:** `.github/workflows/ci.yml`
- Parallel runs on same ref can race. Should use `concurrency` group.

### VULN-052: CI/CD — Build Args Include GitHub Context Data
- **Severity:** Medium | **Confidence:** 70% | **CWE:** CWE-94
- **File:** `.github/workflows/release.yml:107-111`
- `github.event.head_commit.timestamp` in build metadata — commit-author controlled.

### VULN-053: API — DLP Pattern Test ReDoS
- **Severity:** Medium | **Confidence:** 70% | **CWE:** CWE-1333
- **File:** `internal/dashboard/dlp_handlers.go`
- User-supplied regex in DLP pattern test could cause catastrophic backtracking.

### VULN-054: API — AI Endpoint URL Validation Bypassable via DNS Rebinding
- **Severity:** Medium | **Confidence:** 70% | **CWE:** CWE-918
- Same as VULN-019.

### VULN-055: Tenant — Header-Based Resolution Bypass (Same as VULN-026)
- **Severity:** Medium | **Confidence:** 75% | **CWE:** CWE-840
- See VULN-026.

### VULN-056: Rate Limiting — Per-IP Only, No Session/User Scope
- **Severity:** Medium | **Confidence:** 80% | **CWE:** CWE-307
- Same as VULN-042.

### VULN-057: Docker — No Health Check in docker-compose.yml
- **Severity:** Medium | **Confidence:** 85% | **CWE:** CWE-665
- **File:** `docker-compose.yml`
- Main `docker-compose.yml` missing `healthcheck` on services.

### VULN-058: Docker — Docker Socket Not Mounted (Positive)
- **Severity:** Info | **Confidence:** 100%
- **File:** `docker-compose.prod.yml`
- Docker socket is NOT mounted in production — correctly secured.

### VULN-059: IaC — K8s Liveness Probe Points to Dashboard Port
- **Severity:** Medium | **Confidence:** 70% | **CWE:** CWE-665
- **File:** `contrib/k8s/deployment.yaml:60`
- Liveness probe on port 9443 may mask WAF proxy failures.

### VULN-060: IaC — Missing Pod Disruption Budget
- **Severity:** Medium | **Confidence:** 85% | **CWE:** CWE-250
- **File:** All Kubernetes deployment manifests
- No PDB for HA during node drains.

### VULN-061: IaC — Missing NetworkPolicy
- **Severity:** Medium | **Confidence:** 85% | **CWE:** CWE-250
- **File:** All Kubernetes deployment manifests
- No NetworkPolicy restricts pod-to-pod traffic.

### VULN-062: IaC — Missing Vertical Pod Autoscaler
- **Severity:** Medium | **Confidence:** 85% | **CWE:** CWE-400
- **File:** All Kubernetes deployment manifests
- No VPA for automatic resource management.

### VULN-063: IaC — Missing Pod Topology Spread Constraints
- **Severity:** Medium | **Confidence:** 85% | **CWE:** CWE-250
- **File:** All Kubernetes deployment manifests
- No explicit topology spread for sophisticated pod distribution.

### VULN-064: API — GeoIP Lookup Lacks Rate Limiting
- **Severity:** Medium | **Confidence:** 80% | **CWE:** CWE-307
- **File:** `internal/dashboard/geoip_handlers.go`
- GeoIP lookup endpoint has no rate limiting. Enumeration possible.

### VULN-065: SMTP Password Could Leak in Error Logs
- **Severity:** Medium | **Confidence:** 70% | **CWE:** CWE-200
- **File:** `internal/dashboard/dashboard.go:2231-2285`
- Error during webhook save could expose SMTP password in logs.

### VULN-066: ATO Per-Email Counter Reset on Password Change
- **Severity:** Medium | **Confidence:** 60% | **CWE:** CWE-307
- See VULN-025.

### VULN-067: File Upload — MaxFileSize Check After Partial Read
- **Severity:** Low | **Confidence:** 65% | **CWE:** CWE-400
- **File:** `internal/layers/dlp/layer.go:426-439`
- `io.LimitReader` provides guard, but size check after read is suboptimal.

### VULN-068: Tenant Rate Limiter Counter Reset on Auto-Ban Expiry
- **Severity:** Low | **Confidence:** 70% | **CWE:** CWE-840
- **File:** `internal/layers/ratelimit/ratelimit.go:274-293`
- Related to VULN-023.

### VULN-069: Tenant Resolution Order Header-Based Impersonation
- **Severity:** Low | **Confidence:** 55% | **CWE:** CWE-840
- **File:** `internal/tenant/middleware.go:335-359`
- Related to VULN-026.

### VULN-070: Client Report JSON Unmarshal into map[string]any
- **Severity:** Low | **Confidence:** 40% | **CWE:** CWE-943
- **File:** `internal/layers/clientside/report_handler.go:16`
- In-memory only with 1000-entry cap. Very limited attack surface.

---

## Low Findings (17)

### VULN-071: WebSocket — No Subprotocol Validation
- **Severity:** Low | **Confidence:** 80%
- **Reference:** VULN-001 context

### VULN-072: WebSocket — No Extension Header Validation
- **Severity:** Low | **Confidence:** 80%
- **Reference:** VULN-001 context

### VULN-073: Rate Limiting — Bucket Count Drift After Cleanup
- **Severity:** Low | **Confidence:** 75%
- **Reference:** VULN-023 context

### VULN-074: Dashboard README Documents Incorrect Origin Validation Behavior
- **Severity:** Low | **Confidence:** 90%
- **File:** `internal/layers/websocket/README.md:26`
- README says "Empty = allow all" but code implements "Empty = same-origin policy".

### VULN-075: sync.Pool Context Field Reset Completeness Risk
- **Severity:** Low | **Confidence:** 70%
- **File:** `internal/engine/context.go:246-293`
- Future field additions without corresponding `ReleaseContext()` reset could leak.

### VULN-076: Example Domains Not Updated in Kubernetes Manifests
- **Severity:** Low | **Confidence:** 90%
- **File:** `examples/kubernetes/configmap.yaml`, `examples/kubernetes/ingress.yaml`

### VULN-077: Tenant Resolution Header-Based Impersonation (Low Confidence)
- **Severity:** Low | **Confidence:** 55%
- **Reference:** VULN-026 context

### VULN-078: SMTP Password in Error Logs (Low Confidence)
- **Severity:** Low | **Confidence:** 70%
- **Reference:** VULN-065 context

### VULN-079: insecureSkipVerify in CLI Test
- **Severity:** Low | **Confidence:** 95%
- **File:** `cmd/guardianwaf/main_cli_test.go:981`
- Test-only code, not production.

### VULN-080: Cluster Auth Secret Warning Logged Without Value
- **Severity:** Low | **Confidence:** 90%
- **File:** `internal/cluster/cluster.go:814`
- Warning does NOT include the secret value. Informational only.

### VULN-081: Build Args Include GitHub Context Data (Low)
- **Severity:** Low | **Confidence:** 70%
- **Reference:** VULN-052 context

### VULN-082: Optional TLS Certificate May Cause Issues
- **Severity:** Low | **Confidence:** 70%
- **File:** `contrib/k8s/deployment.yaml:60`

### VULN-083: Missing Vertical Pod Autoscaler (Low)
- **Severity:** Low | **Confidence:** 85%
- **Reference:** VULN-062 context

### VULN-084: Missing Pod Topology Spread Constraints (Low)
- **Severity:** Low | **Confidence:** 85%
- **Reference:** VULN-063 context

### VULN-085: API Validation Layer Uses any for JSON Parsing
- **Severity:** Low | **Confidence:** 20%
- **File:** `internal/layers/apivalidation/layer.go:604-605`
- Schema validation immediately follows parsing. Low risk.

### VULN-086: Math/rand in Attack Simulation Tool
- **Severity:** Low | **Confidence:** 90%
- **File:** `scripts/attack-simulation/main.go:12`
- Test tool, not production. Acceptable.

### VULN-087: Dashboard README Inconsistent (COR-WS-OBS-3)
- **Severity:** Low | **Confidence:** 90%
- **File:** `internal/layers/websocket/README.md:26`
- Same as VULN-074.

---

## Eliminated Findings (False Positives)

The following were reported by Phase 2 but are NOT vulnerabilities after verification:

| Finding | Reason Eliminated |
|---------|-------------------|
| RACE-001 (IP ACL Count++) | FALSE POSITIVE — Count is protected by `Layer.mu` mutex (line 30 comment confirms) |
| Math/rand in attack simulation | INFO — Testing tool, not production |
| sync.Map in rate limiting | SECURE — Appropriate for append-mostly workloads (ADR-0029) |
| JWT alg "none" rejection | SECURE — Function explicitly rejects empty/none alg |
| JWT algorithm confusion | SECURE — HMAC blocked when asymmetric keys configured |
| WebSocket origin validation (sc-lang-go claim) | MISINTERPRETED — `isAllowedOrigin` is dead code in default config; sc-websocket is correct |
| GraphQL security controls | SECURE — max depth, complexity, introspection blocking all present |
| CRS regex timeout | SECURE — Go regexp is RE2 (linear); 5s timeout also applied |
| SSRF protection in proxy/alerting/SIEM | SECURE — `IsPrivateOrReservedIP` + DNS re-validation present |
| Cookie security attributes | SECURE — HttpOnly, Secure, SameSite all correctly set |
| Open redirect prevention | SECURE — Host header validated, protocol-relative URLs stripped |
| Header injection | SECURE — Go net/http panics on CRLF; `setSafeHeader` provides defense-in-depth |
| XSS | SECURE — React JSX auto-escaping, `escapeHTML()` in Go |
| Mass assignment | SECURE — Typed structs with explicit field allowlists |
| Authorization/IDOR | SECURE — All findings were positive confirmations |
| CSRF (dashboard) | SECURE — Origin/Referer validation + SameSite=Strict |
| Deserialization | SECURE — Safe formats only (JSON, gob for local disk) |
| SSTI | N/A — No template engine used |
| SQL injection | N/A — No SQL database |
| XXE | N/A — No XML parsing |
| RCE | N/A — No RCE vectors |
| LDAP injection | N/A — No LDAP usage |
| Secrets in test files | FALSE POSITIVE — Test/demo values only |
| CMDi in Docker client | FALSE POSITIVE — `isSafeContainerRef()` allowlists all IDs |
| Hardcoded credentials | SECURE — All from config/env, not hardcoded |
| YAML unsafe tags | FALSE POSITIVE — Documentary only, parser doesn't support |
| `dangerouslySetInnerHTML` in CodeBlock | FALSE POSITIVE — Content is pre-HTML-encoded before use |
| Theme localStorage | INFO — Non-sensitive UI preference |

---

## Top 5 Immediate Actions

1. **Fix WebSocket origin validation bypass** (`internal/layers/websocket/websocket.go:188`) — remove the `if len > 0` guard so `isAllowedOrigin` always runs
2. **Add auth-endpoint rate limits** — no brute force protection on `/login` without ATO enabled
3. **Require TLS for cluster communication** when `AuthSecret` is configured (`internal/cluster/cluster.go`)
4. **Pin GitHub Actions to commit SHAs** — top supply chain risk
5. **Add SAST + secret scanning to CI** — security vulnerabilities may be merged undetected