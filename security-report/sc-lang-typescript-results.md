# sc-lang-typescript Security Scan Results

**Scanner:** sc-lang-typescript (TypeScript/JavaScript Security Deep Scan)
**Target:** `internal/dashboard/ui/src/` (React dashboard) + `website/src/` (landing site)
**Files Scanned:** 55 files (.ts/.tsx)
**Date:** 2026-04-16

---

## Summary

| Category | Count |
|----------|-------|
| Critical | 0 |
| High | 0 |
| Medium | 1 |
| Low | 1 |
| Total | 2 |

---

## Findings

### Finding: TS-001

- **Title:** `dangerouslySetInnerHTML` with pre-escaped static content in CodeBlock
- **Severity:** Low
- **Confidence:** 85
- **File:** `website/src/components/ui/code-block.tsx:137`
- **Vulnerability Type:** CWE-79 (Cross-site Scripting)
- **Description:**
  The `CodeBlock` component uses `dangerouslySetInnerHTML` to render syntax-highlighted code. The code path correctly HTML-encodes all input before adding span markup for highlighting (lines 16-20), so the final output is safe. However, `dangerouslySetInnerHTML` is used even for what should be safe content. The comment on line 125-127 states the code only processes developer-authored static code constants, not user-controlled data.

  The risk is low because:
  1. All user-provided content is pre-escaped via `.replace(/&/g, '&amp;')` etc.
  2. Span injection only adds syntax tokens, no user-controlled values
  3. The `code` prop comes from static content props, not dynamic user input

- **Remediation:**
  Consider using React's built-in text rendering for lines instead of `dangerouslySetInnerHTML`. Each line can be split and rendered as `<span className="token-*">` children. This avoids any need for `dangerouslySetInnerHTML` even in the safety-reviewed code path.

  ```tsx
  {/* Replace dangerouslySetInnerHTML with safe React children */}
  <span>{line || '\n'}</span>
  ```

  Alternatively, keep the current pattern with a documented safety invariant, but add a lint rule to prevent new usages elsewhere.

- **References:**
  - CWE-79: https://cwe.mitre.org/data/definitions/79.html
  - React documentation on `dangerouslySetInnerHTML`: https://react.dev/reference/react/dom-components#dangerouslysetinnerhtml

---

### Finding: TS-002

- **Title:** Theme preference stored in localStorage (low-risk non-sensitive data)
- **Severity:** Low
- **Confidence:** 90
- **File:** `internal/dashboard/ui/src/hooks/use-theme.ts:8`
- **Vulnerability Type:** CWE-922 (Insecure Storage)
- **Description:**
  The `useTheme` hook stores the user's theme preference in `localStorage` under the key `gwaf-theme`. This is a common pattern for persisting UI preferences. The stored value is limited to `'light' | 'dark'` and is not used for authentication, authorization, or any security-sensitive purpose.

  While `localStorage` is accessible to XSS attacks, the theme value itself carries no security implications. This is by design (user preference persistence) and not a vulnerability per OWASP guidelines for client-side preference storage.

- **Remediation:**
  No remediation required for this specific case. If theme persistence is needed and CSRF is a concern, consider using a cookie with appropriate SameSite attributes. However, since the value is non-sensitive (theme preference only), localStorage is acceptable.

- **References:**
  - OWASP: https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#local-storage
  - CWE-922: https://cwe.mitre.org/data/definitions/922.html

---

## Excluded / Safe Patterns Verified

The following patterns were checked and found absent (or safe) across all scanned files:

| Pattern | Status |
|---------|--------|
| `innerHTML = ` assignment | Not found |
| `document.write()` / `document.writeln()` | Not found |
| `eval()` / `new Function()` / `setTimeout(string, ...)` | Not found |
| Hardcoded API keys, passwords, or secrets | Not found |
| `localStorage` / `sessionStorage` for auth tokens | Not found (theme only) |
| JWT stored in localStorage | Not found |
| SQL/NoSQL injection in frontend code | Not found (backend concern only) |
| SSRF (client-side fetch to internal IPs) | Not found |
| Dynamic `require()` / `import()` with user input | Not found |
| Prototype pollution (unmitigated) | Not found |
| Missing CSRF tokens on state-changing operations | Not found |
| ReDoS patterns (catastrophic regex) | Not found |
| Cookie without HttpOnly/Secure/SameSite | Not found (no cookies used client-side) |

## Notable Secure Patterns

- **SSE event filtering** (`use-sse.ts:30-32`): The event source only processes messages that pass a structural validation (`data.action && data.client_ip`), ignoring malformed messages. Safe pattern.
- **Prototype pollution defense** (`rules.tsx:391-404`): The rule editor explicitly filters `__proto__`, `constructor`, and `prototype` from JSON-parsed condition values before merging. Strong defense.
- **API design**: All sensitive operations (tenant management, API key rotation) are server-side; the frontend never holds or transmits raw secrets beyond display.

---

*End of report. No critical or high severity issues found.*
