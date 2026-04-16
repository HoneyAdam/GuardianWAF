# Sensitive Data Exposure Scan Results

**Scanner:** sc-data-exposure (Sensitive Data Exposure Detector)
**Date:** 2026-04-16
**Project:** GuardianWAF
**Files Scanned:** internal/layers/dlp/, internal/layers/response/, internal/alerting/, internal/config/, internal/dashboard/, internal/engine/

---

## Summary

| Category | Count |
|----------|-------|
| Critical Issues | 0 |
| High Issues | 0 |
| Medium Issues | 1 |
| Low Issues (Info) | 1 |

**Result:** OVERALL SECURE — No critical sensitive data exposure found.

---

## Detailed Findings

### EXPOSE-001: HTTP Webhook URLs Allow Credentials in Cleartext

- **Title:** HTTP Webhook URL Exposes Credentials
- **Severity:** Medium
- **Confidence:** 85
- **File:** `internal/alerting/webhook.go:96-98`
- **Vulnerability Type:** CWE-200 (Information Disclosure)
- **Description:** When a webhook target uses an HTTP (not HTTPS) URL, a warning is printed to stdout but no blocking occurs. If credentials are placed in webhook custom headers, they could be transmitted in cleartext over the network.
- **Impact:** Credentials in webhook headers could be intercepted by network attackers if HTTP is mistakenly used instead of HTTPS.
- **Remediation:** The warning is appropriate but non-blocking. Consider rejecting HTTP webhook URLs at validation time rather than just warning.
- **References:** https://cwe.mitre.org/data/definitions/200.html

### EXPOSE-002: Cluster Auth Secret Warning Logged Without Value

- **Title:** Cluster Auth Secret Configuration Warning
- **Severity:** Low (Informational)
- **Confidence:** 90
- **File:** `internal/cluster/cluster.go:814`
- **Vulnerability Type:** CWE-532 (Log File Information Disclosure)
- **Description:** A warning is logged when `AuthSecret` is configured without TLS — the message states the secret "will be sent in cleartext" but does NOT include the actual secret value. The auth secret itself is only compared via `subtle.ConstantTimeCompare` and never logged.
- **Impact:** Informational warning only — no secret value exposed. Attackers learn that an auth mechanism exists, but cannot derive the secret.
- **Remediation:** Already secure. The warning is appropriate for operational awareness.
- **References:** https://cwe.mitre.org/data/definitions/532.html

---

## Positive Security Findings

### 1. DLP Layer — Sensitive Data Properly Masked

- **Location:** `internal/layers/dlp/patterns.go:256, 276`
- **Status:** SECURE
- **Details:** When DLP patterns detect sensitive data, the `Value` field is explicitly cleared (`Value: ""`) and only the `Masked` value is retained. This prevents raw sensitive data from being stored in events or logs.

```go
match := Match{
    Type:     pattern.Type,
    Severity: pattern.Severity,
    Value:    "", // Cleared — only Masked retained
    Masked:   r.maskValue(value, pattern),
    Position: loc[0],
    Length:   loc[1] - loc[0],
}
```

### 2. Response Layer — Credit Card / SSN / API Key Masking

- **Location:** `internal/layers/response/masking.go:10-154`
- **Status:** SECURE
- **Details:** Credit card numbers are validated with Luhn algorithm before masking (preserving last 4 digits). SSN patterns are detected and masked as `***-**-XXXX`. API keys are masked showing first 4 and last 4 characters only.

### 3. Response Layer — Stack Trace Stripping

- **Location:** `internal/layers/response/masking.go:156-249`
- **Status:** SECURE
- **Details:** `StripStackTraces()` removes Go (`goroutine N [...]` + `.go:`), Java (exception class names + `.java:`), Python (`Traceback (most recent call last):`), and Node.js (`Error:` + `.js:`/`.ts:`) stack traces from response bodies.

### 4. Error Pages — No Internal Details in Production

- **Location:** `internal/layers/response/errorpage.go:66-94`
- **Status:** SECURE
- **Details:** Production error pages use `productionErrorPage()` which shows only status code text and a generic message. The `escapeHTML()` function prevents XSS in user-controlled detail fields. Development mode shows a clear warning banner.

### 5. Alerting — No Sensitive Data in Webhook Payloads

- **Location:** `internal/alerting/webhook.go:36-46`, `339-457`
- **Status:** SECURE
- **Details:** The `Alert` struct contains only: `timestamp`, `event_id`, `client_ip`, `method`, `path`, `action`, `score`, `findings` (detector names + descriptions only), and `user_agent`. No raw request/response body, no passwords, no tokens, no credit card data.

### 6. Dashboard — API Key Masking in UI

- **Location:** `internal/dashboard/ai_handlers.go:72-88`
- **Status:** SECURE
- **Details:** The AI configuration endpoint returns `api_key_mask` (e.g., `****XXXX`) instead of actual API key, and only includes first/last 4 chars when key is long enough.

```go
if cfg.APIKey != "" {
    if len(cfg.APIKey) > 8 {
        maskedKey = "****" + cfg.APIKey[len(cfg.APIKey)-4:]
    } else {
        maskedKey = "****"
    }
}
```

### 7. Event Struct — No Raw Sensitive Data

- **Location:** `internal/engine/event.go:53-93`
- **Status:** SECURE
- **Details:** The `Event` struct stores only metadata: `ClientIP`, `Method`, `Path`, `Score`, `Findings` (detector/score pairs), `UserAgent` browser/OS/device parsed fields, GeoIP country, and TLS fingerprint data. No raw body content, no tokens, no credentials.

### 8. Webhook SSRF Protection

- **Location:** `internal/alerting/webhook.go:564-628`
- **Status:** SECURE
- **Details:** `ValidateWebhookURL()` requires HTTPS and rejects private/loopback/link-local IPs. DNS resolution is performed and all resulting IPs are checked. SSRF prevention via `webhookSSRFDialContext` validates at connection time.

### 9. Request Context Pool — Sensitive Data Cleared on Release

- **Location:** `internal/engine/context.go:246-293`
- **Status:** SECURE
- **Details:** `ReleaseContext()` clears all fields including `Body`, `BodyString`, `Headers`, `Cookies`, `QueryParams`, and all JA4 TLS fingerprint fields. This prevents cross-request data leakage when contexts are reused from the pool.

### 10. Configuration — No Hardcoded Secrets

- **Location:** `internal/config/defaults.go`
- **Status:** SECURE
- **Details:** All secret fields (API keys, passwords, shared secrets, JWT keys) default to empty strings. Secrets are loaded from YAML files, environment variables (GWAF_* prefix), or CLI flags. Environment variable expansion supports `${VAR}` and `${VAR:-default}` syntax.

---

## Data Flow Analysis

### Request Processing (Ingestion Path)
1. `AcquireContext()` reads body into `ctx.Body` (decompresses gzip/deflate for inspection)
2. DLP layer (Order 550) scans request body for patterns — raw values cleared, only masked retained
3. Detection layers analyze body, add `Findings` (type + score only, no raw data)
4. Response layer masks body before sending to client

### Event Logging Path
1. `NewEvent()` creates event from `RequestContext` — only metadata copied, no body content
2. Events stored in `events.MemoryStore` / `events.FileStore` — no raw sensitive data
3. SSE broadcast uses `json.Marshal(event)` — fields without json tags not serialized

### Alerting Path
1. `HandleEvent()` extracts only safe fields (IP, path, action, score, detector names)
2. Webhook payloads are JSON with only metadata — no raw body, no tokens
3. Email alerts use same safe field set

---

## Conclusion

GuardianWAF demonstrates strong sensitive data protection:
- DLP properly clears raw values, retains only masked representations
- Response masking handles credit cards, SSNs, API keys, and stack traces
- Event structure intentionally omits raw body content
- Request context pool clears all fields on release
- No hardcoded secrets in source code
- Webhook SSRF protection prevents callback attacks

The single medium finding (HTTP webhook warning) is operational awareness, not a vulnerability, since HTTPS is required for new webhook targets.

**Risk Level:** LOW — Project follows secure-by-default practices for sensitive data handling.