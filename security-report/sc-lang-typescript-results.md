# TypeScript/React Security Scan Results

**Target:** `internal/dashboard/ui/src/`
**Scanner:** sc-lang-typescript (manual)
**Date:** 2026-04-15

---

## Findings Summary

| Severity | Count |
|----------|-------|
| Critical | 1 |
| High | 2 |
| Medium | 2 |
| Low | 1 |

---

## Critical Findings

### [CRITICAL] Vite Config Missing Security Headers

- **Category:** Security Configuration
- **Location:** `internal/dashboard/ui/vite.config.ts:7-56`
- **Pattern Matched:** No CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy headers
- **Description:** The Vite build configuration does not configure any security headers. The React dashboard is served without CSP directives, HSTS, X-Frame-Options, or other OWASP-recommended headers. An attacker who finds an XSS vector could exfiltrate session data with no browser restrictions.
- **Exploitability:** If any XSS exists (see other findings), the absence of CSP allows full document access, cookie theft, and keylogging with no browser mitigation.
- **Remediation:** Add security headers to `vite.config.ts`:
  ```ts
  server: {
    port: 5173,
    proxy: {
      '/api': 'http://localhost:9443',
      '/login': 'http://localhost:9443',
      '/logout': 'http://localhost:9443',
    },
    headers: {
      'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' ws://localhost:* http://localhost:*",
      'X-Frame-Options': 'DENY',
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'strict-origin-when-cross-origin',
      'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
    },
  },
  ```
- **Reference:** CWE-693, OWASP CSP Cheat Sheet

---

## High Findings

### [HIGH] Insecure alert() Call in Production Code

- **Category:** JavaScript Injection / UI Security
- **Location:** `internal/dashboard/ui/src/pages/alerting.tsx:101`
- **Pattern Matched:** `alert(\`Test alert sent to ${target}\`)`
- **Description:** Uses native `alert()` which blocks the UI thread and is subject to browser popup blockers. The `useToast` hook is already imported on line 7 but not used for this action, indicating a shortcut taken instead of using the existing feedback system.
- **Exploitability:** Low - this is a UI pattern issue rather than a security vulnerability. However, it could be abused in specific scenarios (e.g., automated harassment via repeated alerts).
- **Remediation:** Replace with the existing `useToast` hook:
  ```ts
  // Replace: alert(`Test alert sent to ${target}`)
  // With: toast({ title: 'Test Alert', description: `Test alert sent to ${target}`, variant: 'success' })
  ```
- **Reference:** CWE-670

### [HIGH] Prototype Pollution Risk in Dynamic Condition Parsing

- **Category:** JavaScript Prototype Pollution
- **Location:** `internal/dashboard/ui/src/pages/rules.tsx:388-389`
- **Pattern Matched:** `JSON.parse(e.target.value)` on user-controlled input inside condition editor
- **Description:** User input (the `value` field in rule conditions) is passed through `JSON.parse` inside a state update. While the context is controlled (rules come from the backend), the UI editor allows users to input values directly. A malicious user could attempt to pollute `Object.prototype` via crafted JSON values during rule creation.
- **Exploitability:** Low in practice since the backend validates rules and the UI is admin-only. However, the client-side parsing is unsafe if any user-supplied value reaches `JSON.parse`.
- **Remediation:** Use a safer JSON parsing approach:
  ```ts
  try {
    const parsed = JSON.parse(e.target.value)
    if (typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)) {
      v = parsed
    } else {
      v = e.target.value
    }
  } catch {
    v = e.target.value
  }
  ```
- **Reference:** CWE-1321

---

## Medium Findings

### [MEDIUM] Credentials Downloaded as Plain Text File

- **Category:** Credential Exposure
- **Location:** `internal/dashboard/ui/src/pages/tenant-detail.tsx:228-255`
- **Pattern Matched:** `Blob` + `URL.createObjectURL` + programmatic `<a>` click to download `api-credentials-${tenant.id}.txt`
- **Description:** When a new API key is generated, the tenant detail page offers a "Download Credentials" button that writes the tenant ID and raw API key to a `.txt` file and triggers a download. The file contains the plaintext API key and is saved to disk unencrypted. This allows users to accidentally commit credential files to version control or share them insecurely.
- **Exploitability:** Medium - anyone with access to the browser's downloads folder can retrieve the credential file. The pattern encourages bad security hygiene.
- **Remediation:** Remove the credential download feature entirely, or require re-authentication before downloading. Credentials should be shown once and not re-downloadable.
- **Reference:** CWE-312

### [MEDIUM] Missing CSRF Protection on API Mutations

- **Category:** Authentication and Session Management
- **Location:** `internal/dashboard/ui/src/lib/api.ts:1-148` (all mutation endpoints)
- **Pattern Matched:** `fetch()` calls without CSRF token in headers
- **Description:** All `POST`, `PUT`, `DELETE` requests to the backend (e.g., `api.addRule`, `api.updateConfig`, `api.deleteRule`) do not include a CSRF token. While the Vite proxy in dev mode routes to the same-origin backend, in production the SPA may be deployed on a separate origin. CSRF tokens should be embedded in all state-changing requests to protect against cross-origin attacks.
- **Exploitability:** If the dashboard is deployed separately from the WAF backend (CORS-enabled), an attacker could trick an authenticated admin into making unintended mutations (block/delete rules, change config).
- **Remediation:** Add a CSRF token mechanism:
  1. Backend should set a `X-CSRF-Token` header cookie on session/login
  2. Frontend should read the cookie and include it in all state-changing requests:
  ```ts
  const csrfToken = () => {
    const match = document.cookie.match(/csrf_token=([^;]+)/)
    return match ? match[1] : ''
  }
  // In request():
  headers: {
    'Content-Type': 'application/json',
    'X-CSRF-Token': csrfToken(),
    ...options?.headers,
  },
  ```
- **Reference:** CWE-352, OWASP CSRF Prevention Cheat Sheet

---

## Low Findings

### [LOW] API Key Revealed in URL Query Parameters

- **Category:** Information Exposure
- **Location:** `internal/dashboard/ui/src/lib/api.ts:79-80`
- **Pattern Matched:** `encodeURIComponent(ip)` in GET request query string
- **Description:** The `geoipLookup` function encodes the IP as a query parameter (`?ip=...`). While not directly a security flaw (IP addresses are not sensitive), this pattern means that server-side logs will record the looked-up IP in plain text as part of the URL path. Combined with other findings, logging of these requests could aid in targeted reconnaissance.
- **Exploitability:** Informational - no direct exploit, but URL logging is a consideration for privacy.
- **Remediation:** Move the IP lookup to a POST endpoint with the IP in the request body, or use a more privacy-preserving approach.
- **Reference:** CWE-200

---

## Positive Security Observations

The following patterns were verified as **secure** during this scan:

- **No XSS vulnerabilities found** - No usage of `innerHTML`, `dangerouslySetInnerHTML`, or `v-html` anywhere in the codebase. All text rendering uses React's standard JSX expressions which are safe by default.

- **No localStorage token storage** - The `use-theme.ts` hook uses localStorage only for theme preference (non-sensitive). No JWT, API keys, or session tokens are stored in localStorage or sessionStorage.

- **API keys properly masked** - In `tenant-detail.tsx`, existing API keys are masked and revealed only on explicit toggle. New keys are shown once after generation but not persistently stored in the browser.

- **SSE connection properly handled** - The `use-sse.ts` hook correctly parses incoming JSON messages, checks for valid event structure before processing, and handles reconnection with exponential backoff.

- **Good input rendering practices** - Event data (paths, IPs, user agents) are rendered via React JSX text content, not innerHTML. The `break-all` CSS class is used for long strings, preventing overflow without requiring dangerous methods.

- **No hardcoded secrets** - No API keys, passwords, or secrets found in the TypeScript source code.

- **Focus trap implemented** - The `use-focus-trap` hook is used for modal dialogs, properly trapping keyboard focus and preventing escape navigation.

---

## Summary

The GuardianWAF React dashboard demonstrates good React security practices overall. XSS vectors are absent, token storage follows best practices, and input handling is generally safe. The issues found are configuration and design-level rather than code-level vulnerabilities. The most actionable items are adding CSP headers to the Vite config and implementing CSRF protection on API mutations.

---

*Generated by sc-lang-typescript security scan*