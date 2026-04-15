# SSRF Security Scan Results

**Scanner:** sc-ssrf
**Target:** GuardianWAF (Pure Go WAF)
**Date:** 2026-04-15

---

## Summary

**No SSRF vulnerabilities found.**

GuardianWAF has comprehensive SSRF protection across all HTTP outbound request paths. The protection is applied at both URL validation time (at configuration/initialization) and at connection time (DNS re-resolution prevention via `SSRFDialContext`).

---

## Protection Mechanisms Found

### 1. Proxy Layer — SSRFDialContext (Primary SSRF Barrier)
**Location:** `internal/proxy/target.go:91-125`

`SSRFDialContext()` returns a custom `DialContext` function that:
- Validates all resolved IPs against private/reserved ranges at connection time
- Prevents DNS rebinding attacks (TOCTOU gap closure)
- Blocks: loopback, private (10.x, 172.16-31.x, 192.168.x), link-local unicast, link-local multicast, interface-local multicast

`NewTarget()` (`target.go:142-145`) validates target URLs before accepting them:
```go
if !allowPrivateTargets.Load() {
    if err := IsPrivateOrReservedIP(u.Host); err != nil {
        return nil, err
    }
}
```

`IsPrivateOrReservedIP()` (`target.go:31-55`) resolves the hostname and checks all resulting IPs.

### 2. JWKS URL Validation
**Location:** `internal/layers/apisecurity/jwt.go:1065-1106`

`validateJWKSURL()` is called at validator initialization time (`jwt.go:98`) before any fetch begins:
- Rejects `localhost`, `*.internal`, `*.local`, `*.localhost`
- Rejects literal private/loopback/link-local IPs
- Resolves DNS and checks all resulting IPs
- Returns error on first private IP found

`fetchJWKS()` uses a dedicated HTTP client with a 10-second timeout (`jwt.go:380-387`).

### 3. Threat Intel Feed URL Validation
**Location:** `internal/layers/threatintel/feed.go:410-441`

`validateFeedURL()` is called in `loadURL()` (`feed.go:173-175`) before any feed fetch:
- Same protection pattern as JWKS validation
- Rejects private/loopback/link-local IPs at init time
- `AllowPrivateURLs` field (set only in tests) bypasses this

### 4. AI Provider Catalog URL Validation
**Location:** `internal/ai/provider.go:203-208`

`FetchCatalog()` validates the catalog URL before fetching:
```go
if err := validateURLNotPrivate(catalogURL); err != nil {
    return nil, fmt.Errorf("catalog URL rejected: %w", err)
}
```

`validateURLNotPrivate()` (`provider.go:271-289`) follows the same pattern.

### 5. GeoIP Download URL Validation
**Location:** `internal/geoip/geoip.go:263-268`

`downloadDB()` validates the GeoIP download URL before fetching, using the same `validateURLNotPrivate()` pattern.

---

## Findings

### [INFO] AI Client — Warning-Only SSRF Protection for Inference Endpoints
- **Category:** Server-Side Request Forgery
- **Location:** `internal/ai/client.go:56-63`
- **Description:** When an AI provider endpoint URL is configured to a private/loopback address, `NewClient()` logs a warning but does not reject the configuration. This is a defense-in-depth gap — the operator-configured provider URL is trusted, but a misconfiguration could result in internal network access. The protection is a warning only, not enforcement.
- **Remediation:** Consider treating operator-configured AI endpoints the same as feed/JWKS URLs — validate at initialization and reject private/loopback addresses rather than just warning. Since the AI client makes outbound calls to external AI providers (not inbound user-controlled requests), this is low risk in practice.
- **Severity:** INFO (Low — operator-controlled, not user-controlled)

### [INFO] AI Client — No SSRFDialContext on Inference HTTP Client
- **Category:** Server-Side Request Forgery
- **Location:** `internal/ai/client.go:67-88`
- **Description:** The AI inference HTTP client uses a plain `&http.Transport{}` without `DialContext`拦截. Unlike the proxy's `SSRFDialContext`, the AI client's transport does not perform per-connection IP validation. A DNS rebinding attack against the AI provider hostname could theoretically bypass the initialization-time warning.
- **Remediation:** Consider wrapping the AI client's transport with a DNS-validating dialer, similar to `SSRFDialContext`, to ensure connection-time IP validation.
- **Severity:** INFO (Low — AI provider hostnames are operator-configured and relatively static)

---

## HTTP Clients Without User-Controlled URLs (Trusted Paths)

These HTTP clients make outbound calls to operator-configured URLs — no SSRF risk:
- `internal/alerting/webhook.go:82` — Webhook delivery (operator configures URL)
- `internal/cluster/cluster.go:217` — Cluster gossip (operator configures endpoints)
- `internal/docker/client.go:345` — Docker socket, no outbound HTTP
- `internal/acme/client.go:81` — ACME/Let's Encrypt (operator configures, protocol-standard)
- `internal/clustersync/manager.go:88` — Cluster sync (operator configures)
- `internal/proxy/health.go:48` — Active health checks (configured upstream targets already protected by SSRFDialContext)
- `internal/layers/canary/canary.go:130` — Canary health checks (operator configures)
- `internal/layers/cache/layer.go:82` — Cache layer (operator configures)
- `internal/layers/siem/exporter.go` — SIEM export (operator configures)
- `internal/tls/ocsp.go:42` — OCSP stapling (TLS infrastructure, not SSRF-relevant)

---

## Conclusion

GuardianWAF's SSRF protection is comprehensive and well-implemented:
- **Proxy layer** has the strongest protection with SSRFDialContext (connection-time validation, DNS rebinding prevention)
- **Configuration-time validation** exists for JWKS, threat feeds, AI catalog, and GeoIP downloads
- **No user-controlled URL SSRF vector found** — all HTTP client paths either validate URLs or operate on operator-configured endpoints

The AI client inference has warning-only SSRF checks (not blocking), but this is low risk because the AI provider URL is operator-configured, not user-controlled.