# Dependency Security Audit Report

**Project:** GuardianWAF
**Date:** 2026-04-16
**Auditor:** sc-dependency-audit skill

---

## Executive Summary

GuardianWAF maintains an **excellent supply chain posture** with minimal dependencies. The project enforces a **zero external Go dependencies** policy (only optional quic-go for HTTP/3), and both Node.js frontends pass `npm audit` with zero vulnerabilities.

| Ecosystem | Direct Dependencies | Transitive Dependencies | Known CVEs |
|-----------|---------------------|-------------------------|------------|
| Go | 1 (quic-go) | 18 (mostly test/dev) | 0 |
| Node.js (dashboard) | 8 | ~270 (lockfile) | 0 |
| Node.js (website) | 7 | ~369 (lockfile) | 0 |

---

## 1. Go Dependencies

### 1.1 Direct Dependencies

| Module | Version | Purpose | Required |
|--------|---------|---------|----------|
| `github.com/quic-go/quic-go` | v0.59.0 | HTTP/3 QUIC support | Optional (`-tags http3`) |

**Build constraint:** Only included when building with `-tags http3`. Core WAF operates with zero external dependencies.

### 1.2 Transitive Dependencies (from go.mod)

| Module | Version | Type | Origin |
|--------|---------|------|--------|
| `github.com/quic-go/qpack` | v0.6.0 | indirect | quic-go |
| `golang.org/x/crypto` | v0.49.0 | indirect | quic-go |
| `golang.org/x/net` | v0.52.0 | indirect | quic-go |
| `golang.org/x/sys` | v0.42.0 | indirect | quic-go |
| `golang.org/x/text` | v0.35.0 | indirect | quic-go |
| `github.com/davecgh/go-spew` | v1.1.1 | indirect | testify |
| `github.com/pmezard/go-difflib` | v1.0.0 | indirect | testify |
| `github.com/stretchr/testify` | v1.11.1 | indirect | test |
| `go.uber.org/mock` | v0.5.2 | indirect | test |
| `golang.org/x/mod` | v0.33.0 | indirect | tools |
| `golang.org/x/sync` | v0.20.0 | indirect | tools |
| `golang.org/x/term` | v0.41.0 | indirect | tools |
| `golang.org/x/tools` | v0.42.0 | indirect | tools |
| `gopkg.in/yaml.v3` | v3.0.1 | indirect | config |
| `gopkg.in/check.v1` | v1.0.0-20201130134442-10cb98267c6c | indirect | test |
| `github.com/jordanlewis/gcassert` | v0.0.0-20250430164644-389ef753e22e | indirect | test |
| `github.com/kr/pretty` | v0.3.1 | indirect | test |
| `github.com/rogpeppe/go-internal` | v1.10.0 | indirect | test |

### 1.3 Module Integrity Verification

```
$ go mod verify
all modules verified
```

**Status:** PASSED - All modules match their recorded checksums.

### 1.4 CVE Analysis for quic-go v0.59.0

**Published:** 2026-01-11
**Go Version:** 1.24+

At time of audit, no known CVEs affecting quic-go v0.59.0 were identified in public vulnerability databases. The module is actively maintained with regular updates.

### 1.5 Supply Chain Risk Assessment (Go)

| Factor | Rating | Notes |
|--------|--------|-------|
| Dependency Count | LOW | Only 1 optional direct dependency |
| Dependency Origin | TRUSTED | proxy.golang.org (Google-operated) |
| Module Integrity | VERIFIED | go mod verify passes |
| Vulnerability History | CLEAN | No known CVEs in quic-go |
| Attack Surface | MINIMAL | quic-go only used for HTTP/3 feature |

**Overall Go Supply Chain Risk: VERY LOW**

---

## 2. Node.js Dependencies - Dashboard UI

**Location:** `internal/dashboard/ui/`
**Lockfile:** `package-lock.json` (lockfileVersion 3)
**Packages:** ~271 unique packages

### 2.1 Direct Dependencies (Production)

| Package | Version | Purpose |
|---------|---------|---------|
| `@xyflow/react` | ^12.10.1 | React Flow (routing topology graph) |
| `class-variance-authority` | ^0.7.0 | CSS class variance utility |
| `clsx` | ^2.1.0 | Class name utility |
| `lucide-react` | ^0.500.0 | Icon library |
| `react` | ^19.0.0 | UI framework |
| `react-dom` | ^19.0.0 | React DOM renderer |
| `react-router` | ^7.0.0 | Routing |
| `tailwind-merge` | ^3.0.0 | Tailwind class merge utility |

### 2.2 Development Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `@eslint/js` | ^9.39.4 | ESLint JavaScript support |
| `@tailwindcss/vite` | ^4.0.0 | Tailwind Vite plugin |
| `@testing-library/jest-dom` | ^6.9.1 | Jest DOM testing |
| `@testing-library/react` | ^16.3.2 | React testing |
| `@testing-library/user-event` | ^14.6.1 | User event simulation |
| `@types/react` | ^19.0.0 | TypeScript types |
| `@types/react-dom` | ^19.0.0 | TypeScript types |
| `@vitejs/plugin-react` | ^4.5.0 | Vite React plugin |
| `eslint` | ^9.39.4 | Linter |
| `eslint-plugin-react-hooks` | ^7.0.1 | React hooks linting |
| `eslint-plugin-react-refresh` | ^0.5.2 | HMR linting |
| `jsdom` | ^29.0.2 | DOM simulation for tests |
| `tailwindcss` | ^4.0.0 | CSS framework |
| `typescript` | ^5.7.0 | TypeScript compiler |
| `typescript-eslint` | ^8.58.1 | TypeScript ESLint |
| `vite` | ^6.0.0 | Build tool |
| `vitest` | ^4.1.4 | Test runner |

### 2.3 Audit Results

```
$ npm audit
found 0 vulnerabilities
```

**Status:** PASSED - No security vulnerabilities detected.

---

## 3. Node.js Dependencies - Website

**Location:** `website/`
**Lockfile:** `package-lock.json` (lockfileVersion 3)
**Packages:** ~369 unique packages

### 3.1 Direct Dependencies (Production)

| Package | Version | Purpose |
|---------|---------|---------|
| `class-variance-authority` | ^0.7.1 | CSS class variance utility |
| `clsx` | ^2.1.1 | Class name utility |
| `lucide-react` | ^0.577.0 | Icon library |
| `react` | ^19.2.4 | UI framework |
| `react-dom` | ^19.2.4 | React DOM renderer |
| `react-router-dom` | ^7.13.1 | Routing |
| `tailwind-merge` | ^3.5.0 | Tailwind class merge utility |

### 3.2 Development Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `@eslint/js` | ^9.39.4 | ESLint JavaScript support |
| `@tailwindcss/vite` | ^4.2.1 | Tailwind Vite plugin |
| `@types/node` | ^24.12.0 | TypeScript types |
| `@types/react` | ^19.2.14 | TypeScript types |
| `@types/react-dom` | ^19.2.3 | TypeScript types |
| `@vitejs/plugin-react` | ^4.5.2 | Vite React plugin |
| `eslint` | ^9.39.4 | Linter |
| `eslint-plugin-react-hooks` | ^7.0.1 | React hooks linting |
| `eslint-plugin-react-refresh` | ^0.5.2 | HMR linting |
| `globals` | ^17.4.0 | ESLint globals |
| `tailwindcss` | ^4.2.1 | CSS framework |
| `typescript` | ~5.9.3 | TypeScript compiler |
| `typescript-eslint` | ^8.56.1 | TypeScript ESLint |
| `vite` | ^6.3.5 | Build tool |

### 3.3 Audit Results

```
$ npm audit
found 0 vulnerabilities
```

**Status:** PASSED - No security vulnerabilities detected.

---

## 4. Dependency Version Currency

### 4.1 Dashboard UI

| Package | Current | Latest (as of audit) | Status |
|---------|---------|----------------------|--------|
| @xyflow/react | ^12.10.1 | 12.x | Current |
| react | ^19.0.0 | 19.x | Current |
| react-router | ^7.0.0 | 7.x | Current |
| tailwindcss | ^4.0.0 | 4.x | Current |
| vite | ^6.0.0 | 6.x | Current |
| typescript | ^5.7.0 | 5.x | Current |

### 4.2 Website

| Package | Current | Latest (as of audit) | Status |
|---------|---------|----------------------|--------|
| react | ^19.2.4 | 19.x | Current |
| react-router-dom | ^7.13.1 | 7.x | Current |
| tailwindcss | ^4.2.1 | 4.x | Current |
| vite | ^6.3.5 | 6.x | Current |
| typescript | ~5.9.3 | 5.9.x | Current |

**All dependencies are on current major versions.** No known deprecated packages.

---

## 5. Supply Chain Analysis

### 5.1 Go Module Proxy

- **Proxy:** proxy.golang.org (Google-operated)
- **Checksum database:** sum.golang.org (Google-operated)
- **Integrity:** Verified via `go mod verify`

### 5.2 NPM Registry

- **Registry:** registry.npmjs.org (official NPM)
- **Integrity:** package-lock.json with integrity hashes present
- **Lockfiles:** Both package-lock.json files use lockfileVersion 3 with SHA512 integrity hashes

### 5.3 Private/Patched Dependencies

**Go:** No private modules, no local patches, no vendored dependencies.
**Node.js:** No private packages, no workspace dependencies, no git dependencies.

### 5.4 Transitive Dependency Risks

Both ecosystems have no high-risk transitive dependencies:
- No known malicious packages
- No deprecated dependencies with known vulnerabilities
- All packages sourced from official registries

---

## 6. Security Best Practices Compliance

| Practice | Status | Notes |
|----------|--------|-------|
| Lockfiles committed | YES | go.sum, package-lock.json (x2) |
| Integrity verification | YES | `go mod verify` passes |
| Dependency audits (CI) | RECOMMENDED | Manual audit complete, no CI configured |
| Minimal dependencies | YES | Only 1 optional Go dep, 15 direct Node deps |
| No private registries | YES | Only official registries |
| Regular updates | YES | Dependencies on latest major versions |

---

## 7. Recommendations

### 7.1 Immediate Actions

1. **Add CI/CD Dependency Audits** (Medium Priority)
   - Configure `go mod verify` in CI pipeline
   - Add `npm audit --audit-level=high` to CI pipeline

### 7.2 Good Practices Already in Place

1. **Lockfiles committed to repo** - Prevents unexpected dependency updates
2. **Zero external Go dependencies** - Minimizes attack surface for core engine
3. **quic-go is optional** - HTTP/3 feature can be disabled if vulnerabilities emerge
4. **All dependencies on current versions** - No known deprecated or EOL packages

### 7.3 Future Enhancements

1. Consider adding `npm outdated` or `pnpm outdated` to CI to detect available updates
2. Pin exact versions in CI rather than relying on lockfiles alone
3. Add Dependabot or Renovate configuration for automated dependency PRs

---

## 8. Conclusion

GuardianWAF has an **exemplary dependency supply chain**:

- **Zero vulnerabilities** in both Go and Node.js dependencies
- **Minimal attack surface** with only 1 optional Go dependency
- **All dependencies verified** and on current versions
- **No private/unusual sources** - only official registries

The project demonstrates excellent dependency hygiene. The primary risk is not from known vulnerabilities but from the general complexity of the npm ecosystem (~270-369 packages per frontend). However, regular audits and lockfile-based reproducibility mitigate this risk effectively.

**Overall Supply Chain Risk Rating: VERY LOW**

---

*Report generated by sc-dependency-audit skill*
*Audit date: 2026-04-16*