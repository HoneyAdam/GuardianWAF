# SSRF Security Scan Results

**Scanner:** sc-ssrf (Server-Side Request Forgery)
**Date:** 2026-04-16
**Files Analyzed:**
- `internal/geoip/geoip.go`
- `internal/alerting/webhook.go`
- `internal/layers/threatintel/feed.go`
- `internal/ai/provider.go`
- `internal/ai/client.go`
- `internal/ai/analyzer.go`
- `internal/layers/siem/exporter.go`
- `internal/proxy/proxy.go`
- `internal/proxy/target.go`
- `internal/proxy/health.go`
- `internal/layers/virtualpatch/nvd.go`
- `internal/layers/canary/canary.go`
- `internal/layers/cache/layer.go`
- `internal/clustersync/manager.go`
- `internal/docker/client.go`
- `internal/cluster/cluster.go`
- `internal/alerting/email.go`
- `internal/tls/ocsp.go`
- `internal/acme/client.go`
- `internal/layers/apisecurity/jwt.go`

---

## Summary

| Finding | Severity | Confidence | Status |
|---------|----------|------------|--------|
| SSRF-001 JWKS: DNS rebinding on periodic refresh (no re-validation) | Medium | 75 | Open |
| SSRF-002 AI Catalog: DNS lookup at setup, no connection-time re-validation | Low | 70 | Open |
| SSRF-003 AI Client: Private/loopback endpoint warning only, no block | Low | 65 | Open |

**Total Findings:** 3

---

## Finding SSRF-001: JWKS Periodic Refresh — No URL Re-validation (DNS Rebinding TOCTOU)

- **Title:** JWKS URL validated at startup but not re-validated on periodic refresh
- **Severity:** Medium
- **Confidence:** 75/100
- **File:** `internal/layers/apisecurity/jwt.go:376-415` (`fetchJWKS()`) and `:458-472` (`refreshJWKSPeriodically()`)
- **Vulnerability Type:** CWE-918 (SSRF) — DNS Rebinding / TOCTOU
- **Component:** `JWTValidator.fetchJWKS()`, `refreshJWKSPeriodically()`

### Description

`validateJWKSURL()` (line 1071) performs strong SSRF validation at **validator creation time**, including DNS resolution to detect hostnames resolving to private IPs. However, `fetchJWKS()` (called both initially and on every periodic refresh) does **not** re-validate the URL before making the HTTP request.

If an attacker controls the JWKS endpoint domain:

1. At `validateJWKSURL()` time: DNS returns a legitimate public IP (passes validation)
2. Between validation and the periodic `fetchJWKS()` call: DNS changes to return a private IP (e.g., `169.254.169.254` AWS metadata, or `10.0.0.5` internal key server)
3. `fetchJWKS()` fetches from the private IP — keys are accepted and trusted

```go
// internal/layers/apisecurity/jwt.go:52
ssrfChecked bool // tracks if JWKS URL SSRF validation passed

// internal/layers/apisecurity/jwt.go:99-104
if err := validateJWKSURL(cfg.JWKSURL); err != nil {
    return nil, fmt.Errorf("JWKS URL rejected: %w", err)
}
v.ssrfChecked = true
go v.fetchJWKS()                           // No URL argument — uses v.config.JWKSURL directly
go v.refreshJWKSPeriodically(5 * time.Minute) // Same — no re-validation

// internal/layers/apisecurity/jwt.go:376-393 (fetchJWKS — called on every refresh)
func (v *JWTValidator) fetchJWKS() {
    if v.config.JWKSURL == "" {
        return
    }
    // No validateJWKSURL() call here — uses cached validation result from startup
    req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.config.JWKSURL, http.NoBody)
    // ... proceeds to fetch from potentially DNS-rebinding URL
```

### Impact

- **Critical Security Impact**: Attacker-serving malicious JWKS keys would be cached and trusted by the WAF
- Could enable: authentication bypass, trust impersonation, signing with attacker-controlled keys
- Requires attacker to control the JWKS endpoint domain's DNS (mid-path attack)
- Window: up to 5 minutes (refresh interval)

### Remediation

Add URL re-validation in `fetchJWKS()` before the HTTP request:

```go
func (v *JWTValidator) fetchJWKS() {
    // Re-validate on each refresh to prevent DNS rebinding
    if err := validateJWKSURL(v.config.JWKSURL); err != nil {
        log.Printf("[jwt] JWKS URL SSRF check failed on refresh: %v", err)
        return
    }
    // ... proceed with fetch
}
```

### References

- https://cwe.mitre.org/data/definitions/918.html
- OWASP SSRF Prevention — "Defense: DNS Rebinding"
- CWE-829: Inclusion of Functionality from Untrusted Control Sphere

---

## Finding SSRF-002: AI Catalog — DNS Lookup at Setup, No Connection-Time Re-validation

- **Title:** AI catalog URL validated at cache setup but not at connection time (TOCTOU)
- **Severity:** Low
- **Confidence:** 70/100
- **File:** `internal/ai/provider.go:199-222` (`FetchCatalog()`) and `:131-153` (`refresh()`)
- **Vulnerability Type:** CWE-918 (SSRF) — TOCTOU DNS Rebinding
- **Component:** `CatalogCache`, `catalogHTTPClient`

### Description

`FetchCatalog()` validates the catalog URL (e.g., `https://models.dev/api.json`) via `validateURLNotPrivate()` which includes DNS resolution. However, the actual HTTP request uses `catalogHTTPClient` — a plain `http.Client` with **no custom `DialContext`** — meaning DNS is re-resolved at connection time with no re-validation.

This creates a TOCTOU window where:
1. `validateURLNotPrivate()` resolves hostname → public IP → passes validation
2. `catalogHTTPClient.Do(req)` re-resolves DNS → private IP (e.g., if models.dev DNS was compromised) → fetches from private IP

```go
// internal/ai/provider.go:198-221
var catalogHTTPClient = &http.Client{Timeout: 30 * time.Second} // No DialContext!

func FetchCatalog(catalogURL string) (*Catalog, error) {
    if !testAllowPrivate {
        if err := validateURLNotPrivate(catalogURL); err != nil {
            return nil, fmt.Errorf("catalog URL rejected: %w", err)  // Validation at setup
        }
    }
    // ...
    resp, err := catalogHTTPClient.Do(req)  // Plain client — DNS re-resolved at connect
```

By contrast, `siem/exporter.go`, `proxy/target.go`, and `alerting/webhook.go` all use a `DialContext`-based transport that validates at connection time.

### Impact

- Narrow TOCTOU window on `models.dev` (default) or custom catalog URL
- If exploited: could serve malicious model metadata (not direct code execution)
- Model catalog data affects dashboard display, not WAF security decisions
- Requires attacker to compromise DNS for a trusted domain

### Remediation

Add a `DialContext`-based transport to `catalogHTTPClient`, similar to `proxy/target.go`:

```go
var catalogHTTPClient = &http.Client{
    Timeout: 30 * time.Second,
    Transport: &http.Transport{
        DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
            // Validate resolved IP at connection time
            dialer := &net.Dialer{Timeout: 10 * time.Second}
            return dialer.DialContext(ctx, network, addr)
        },
    },
}
```

### References

- https://cwe.mitre.org/data/definitions/918.html
- OWASP SSRF Prevention — "Defense: DNS Rebinding"

---

## Finding SSRF-003: AI Client — Private/Loopback Endpoint Warning Only, No Block

- **Title:** AI endpoint private/loopback warning without enforcement
- **Severity:** Low
- **Confidence:** 65/100
- **File:** `internal/ai/client.go:40-90` (`NewClient()`)
- **Vulnerability Type:** CWE-918 (SSRF) — Missing URL validation enforcement
- **Component:** AI `Client`

### Description

`NewClient()` checks if the AI provider `BaseURL` uses HTTP (non-TLS) or targets a private/loopback address, and emits a **log warning** — but does **not** reject the configuration or block the request.

```go
// internal/ai/client.go:49-65
if cfg.BaseURL != "" {
    if u, err := url.Parse(cfg.BaseURL); err == nil {
        if u.Scheme == "http" {
            log.Printf("[ai] WARNING: AI endpoint uses HTTP — API key will be sent in cleartext...")
        }
        host := u.Hostname()
        if ip := net.ParseIP(host); ip != nil {
            if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
                log.Printf("[ai] WARNING: AI endpoint targets a private/loopback address")
                // NO RETURN — request proceeds
            }
        } else if strings.EqualFold(host, "localhost") {
            log.Printf("[ai] WARNING: AI endpoint targets localhost")
            // NO RETURN — request proceeds
        }
    }
}
```

If an operator misconfigures a private AI endpoint (e.g., `http://localhost:11434` for a local LLM, or `http://10.0.0.5/chat`), the WAF will send its API key and batches of security events to that internal service.

### Impact

- If AI BaseURL is misconfigured to a private address, WAF leaks:
  - Configured AI API key
  - Batches of WAF events (IPs, paths, scores, findings, tenant IDs)
- Requires admin misconfiguration; not user-controllable
- Limited to network paths reachable from the WAF host

### Remediation

Apply `validateURLNotPrivate()` with enforcement (not just warning):

```go
if err := validateURLNotPrivate(cfg.BaseURL); err != nil {
    return nil, fmt.Errorf("AI endpoint URL rejected: %w", err)
}
```

Note: `validateURLNotPrivate` already exists in `internal/ai/provider.go` and can be reused.

### References

- https://cwe.mitre.org/data/definitions/918.html
- OWASP SSRF Prevention — "Defense: URL Validation"

---

## Components with Strong SSRF Protection

### GeoIP (`internal/geoip/geoip.go`)

`downloadDB()` validates URLs via `validateURLNotPrivate()` with DNS resolution. TOCTOU note: the URL is validated at `StartAutoRefresh()` call time but re-validation does not occur before each periodic download. However, the validation is re-done on each `downloadDB()` call (not cached), so TOCTOU is limited to the gap between `downloadURL` being checked and the HTTP request being made.

### Threat Intel Feed (`internal/layers/threatintel/feed.go`)

`loadURL()` calls `validateFeedURL()` with DNS resolution. `AllowPrivateURLs` is `yaml:"-"` (never from config file; only programmatically in tests).

### SIEM Exporter (`internal/layers/siem/exporter.go`)

- `validateSIEMEndpoint()` requires HTTPS scheme and validates hostname DNS
- `siemSSRFDialContext()` re-validates at **connection time** — prevents DNS rebinding
- `SkipVerify` config is **ignored** — TLS always enforced

### Webhook Alerting (`internal/alerting/webhook.go`)

- `ValidateWebhookURL()` requires HTTPS and validates hostname DNS
- `webhookSSRFDialContext()` re-validates at **connection time** — prevents DNS rebinding

### Virtual Patch NVD (`internal/layers/virtualpatch/nvd.go`)

`SetBaseURL()` validates via `validateURLNotPrivate()` with DNS resolution. Default is hardcoded NIST URL.

### Proxy Targets (`internal/proxy/target.go`)

- `NewTarget()` validates upstream URL via `IsPrivateOrReservedIP()` before accepting
- `SSRFDialContext()` re-validates at **connection time** and caches the first valid IP — TOCTOU-safe

### Proxy Health Checker (`internal/proxy/health.go`)

`checkAll()` skips private/reserved targets via `IsPrivateOrReservedIP()` before checking. Actual checks also go through `SSRFDialContext`.

### Cluster Sync (`internal/clustersync/manager.go`)

- `validatePeerURL()` requires HTTPS for peer URLs, warns on localhost/loopback, blocks link-local/unspecified
- Private IPs allowed for intra-cluster communication (expected)

### ACME (`internal/acme/client.go`)

Only hardcoded Let's Encrypt URLs. OCSP URLs extracted from certificates (implicitly trusted after cert validation).

### Docker (`internal/docker/client.go`)

Uses Docker CLI exclusively. Container IDs validated via `isSafeContainerRef()` to prevent command injection.

### Email (`internal/alerting/email.go`)

SMTP to admin-configured host. No user-controlled URL.

### Canary (`internal/layers/canary/canary.go`)

Health checks to admin-configured canary upstream. Not user-controllable.

---

## SSRF Protection Comparison

| Feature | JWKS | AI Catalog | AI Client | GeoIP | Threat Intel | SIEM | Webhook |
|---------|------|------------|-----------|-------|--------------|------|---------|
| Block localhost | Yes | Yes | Warning | Yes | Yes | Yes | Yes |
| Block private IPs | Yes | Yes | Warning | Yes | Yes | Yes | Yes |
| DNS resolution check | Yes | **No** | Warning | Yes | Yes | Yes | Yes |
| Re-validate on refresh | **No** | N/A | N/A | Partial | N/A | Yes | Yes |
| Connection-time re-val | **No** | **No** | No | N/A | N/A | Yes | Yes |
| Enforce (not warn) | Yes | Yes | **No** | Yes | Yes | Yes | Yes |

---

## Recommendations

### 1. JWKS Periodic Refresh — Re-validate on Each Fetch (Fix SSRF-001)

Add `validateJWKSURL()` call at the start of `fetchJWKS()`:

```go
func (v *JWTValidator) fetchJWKS() {
    if v.config.JWKSURL == "" {
        return
    }
    // Re-validate on each refresh to prevent DNS rebinding
    if err := validateJWKSURL(v.config.JWKSURL); err != nil {
        log.Printf("[jwt] JWKS URL SSRF check failed: %v", err)
        return
    }
    // ... proceed
}
```

### 2. AI Catalog — Add DialContext to HTTP Client (Fix SSRF-002)

```go
var catalogHTTPClient = &http.Client{
    Timeout: 30 * time.Second,
    Transport: &http.Transport{
        DialContext: catalogDialContext(), // validates at connect time
    },
}
```

### 3. AI Client — Block Private Endpoints (Fix SSRF-003)

Replace warning with enforcement in `NewClient()`:

```go
if err := validateURLNotPrivate(cfg.BaseURL); err != nil {
    return nil, fmt.Errorf("AI endpoint URL rejected: %w", err)
}
```

---

## Cloud Metadata Access Assessment

No direct SSRF vector to cloud metadata endpoints (AWS `169.254.169.254`, GCP `metadata.google.internal`) was found that is exploitable from user-controlled input. The closest vectors are:

1. **SSRF-001 (JWKS)**: TOCTOU on admin-configured JWKS URL — highest impact if exploited
2. **SSRF-002 (AI Catalog)**: TOCTOU on admin-configured catalog URL — low impact
3. **SSRF-003 (AI Client)**: Admin misconfiguration to private endpoint — low impact

All require admin-level access to configure, not user-controlled input.

---

## Conclusion

GuardianWAF implements strong SSRF protection across most outbound HTTP paths. The most significant finding is the **JWKS periodic refresh DNS rebinding gap** (SSRF-001, Medium), where an attacker who compromises the JWKS endpoint domain's DNS could serve malicious keys to be trusted by the WAF.

The AI Catalog (SSRF-002) and AI Client (SSRF-003) findings are lower severity as they require admin misconfiguration and have limited security impact. All findings are in admin-controlled configuration paths, not user-controlled input vectors.

**The proxy, SIEM, webhook, GeoIP, and threat intel layers** all implement best-practice SSRF defenses including connection-time DNS re-validation via custom `DialContext`, HTTPS enforcement, and DNS resolution checks.
