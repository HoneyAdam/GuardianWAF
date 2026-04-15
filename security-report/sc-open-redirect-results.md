# Open Redirect Security Scan - GuardianWAF

**Scan Date:** 2026-04-15
**Target:** Pure Go WAF Codebase
**Skill:** sc-open-redirect

---

## Summary

**No open redirect vulnerabilities found.**

The codebase implements proper redirect sanitization across all redirect handlers. All identified redirects use hardcoded paths, validated paths, or same-host redirects with protocol upgrade only.

---

## Analysis Details

### Redirect Locations Analyzed

| Location | Redirect Type | Sanitization | Status |
|----------|--------------|--------------|--------|
| `internal/dashboard/dashboard.go:226` | Login redirect | Hardcoded `"/login"` | Safe |
| `internal/dashboard/dashboard.go:251,255,270,297` | Post-login redirect | Hardcoded `"/"` | Safe |
| `internal/dashboard/dashboard.go:407` | Logout redirect | Hardcoded `"/login"` | Safe |
| `internal/layers/challenge/challenge.go:168` | Challenge verification | Validated path starts with `/` | Safe |
| `cmd/guardianwaf/main.go:1065` | HTTP to HTTPS | Same host + URI path | Safe |

### Key Security Controls Observed

1. **Dashboard redirects** (`internal/dashboard/dashboard.go`): All redirects use hardcoded absolute paths (`"/"`, `"/login"`) with no user-controlled input.

2. **Challenge layer redirect** (`internal/layers/challenge/challenge.go:163-166`):
   ```go
   if redirect == "" || redirect[0] != '/' || (len(redirect) > 1 && redirect[1] == '/') || strings.ContainsAny(redirect, "\\@") {
       redirect = "/"
   }
   ```
   Validates that redirect must:
   - Start with `/` (blocks absolute URLs)
   - Not start with `//` (blocks protocol-relative URLs)
   - Not contain `\` or `@` (blocks path-based and URL-based bypasses)

3. **HTTP to HTTPS redirect** (`cmd/guardianwaf/main.go:1055-1065`): Uses the validated `host` from virtual host configuration and `uri` (request URI path) to construct the redirect target. The host is validated against configured virtual hosts, and protocol-relative URLs are explicitly stripped.

### No Vulnerable Patterns Found

- No OAuth callbacks or third-party login redirects
- No `next`, `redirect`, `returnTo`, `url`, `dest`, `from` query parameters used in redirects
- No `Location` header set directly from user input
- No path-based redirects that could be manipulated

---

## Conclusion

GuardianWAF is protected against open redirect attacks. All redirect handlers either use hardcoded values or implement proper input validation requiring relative paths only.
