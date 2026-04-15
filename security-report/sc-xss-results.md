# XSS Security Scan Results — GuardianWAF

**Scanner:** sc-xss (skill-based security check)
**Target:** GuardianWAF (Go WAF with React dashboard)
**Date:** 2026-04-15
**Status:** No XSS vulnerabilities found.

---

## Summary

No Cross-Site Scripting (XSS) vulnerabilities were found in the GuardianWAF codebase. The scan covered Go HTTP responses, template usage, React dashboard components, and block/error page rendering.

---

## Detailed Findings

### Go HTTP Responses

All user-controlled input reflected in Go HTML responses is properly escaped using `html.EscapeString()`:

- **`internal/engine/blockpage.go:46`** — `requestID` is passed through `html.EscapeString()` before embedding in the block page HTML.
- **`internal/dashboard/auth.go:164`** — `errMsg` (login error messages) is passed through `html.EscapeString()` before embedding in the login page HTML.
- **`internal/layers/botdetect/collector_handler.go:299`** — `siteKey` is passed through `html.EscapeString()` before use in CAPTCHA challenge page.

### Template Usage

- **No `text/template` usage found.** All template rendering uses `html/template` (auto-escaping) or manual `html.EscapeString()` for string concatenation into HTML.
- No instances of `text/template` imports were detected in the codebase.

### Dashboard React Components

- **No `v-html` or `dangerouslySetInnerHTML` usage found** in any React TSX/TS components under `internal/dashboard/ui/src/`.
- All user-facing text rendering in React components uses default React text interpolation (which is safe by default).
- Event detail display (`event-detail.tsx`) renders `user_agent`, `path`, `matched_value` etc. as plain text — no HTML embedding.

### Block Page / Error Page Rendering

- Block pages are generated server-side using `strings.Builder` with explicit HTML structure — no user input flows into these templates without escaping.
- Challenge pages (CAPTCHA) use hardcoded Cloudflare/hCaptcha URLs — no user-injectable script URLs.
- SSE event streaming uses `json.Marshal()` which escapes strings safely by default.
- CSV export uses a custom `escapeCSV()` function that prevents formula injection and CSV injection.

---

## Security Controls Observed

| Area | Control |
|------|---------|
| Block page | `html.EscapeString()` on request ID |
| Login page | `html.EscapeString()` on error messages |
| CAPTCHA challenge | `html.EscapeString()` on site key + URL allowlist |
| SSE streaming | `json.Marshal()` (inherently safe) |
| CSV export | Formula injection prevention via `escapeCSV()` |
| React dashboard | No `v-html`/`dangerouslySetInnerHTML` usage |

---

## Conclusion

GuardianWAF does not contain XSS vulnerabilities. Input from HTTP requests is properly escaped before being reflected in any HTML response. The codebase demonstrates proper security hygiene for a WAF product that protects against XSS attacks.

**Risk Level:** None
