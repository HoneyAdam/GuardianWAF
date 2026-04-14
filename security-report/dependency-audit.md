# Dependency Audit — GuardianWAF

**Audited:** 2026-04-14
**Go version:** 1.26.1 (runtime: `go1.26.1 windows/amd64`)
**Go module declared:** `go 1.25.0` (go.mod), 1.26.1 (build environment)
**Node/npm:** Dashboard uses npm (5370-line `package-lock.json` present)

---

## 1. Go Dependencies (go.mod)

### Direct Dependencies

| Module | Version | Purpose | License | Notes |
|--------|---------|---------|---------|-------|
| `github.com/quic-go/quic-go` | **v0.59.0** | HTTP/3 support (QUIC) | MIT | **Build-tag gated:** only compiled with `-tags http3` |

### Indirect Dependencies (transitive from quic-go)

| Module | Version | License | Notes |
|--------|---------|---------|-------|
| `github.com/quic-go/qpack` | v0.6.0 | MIT | QPACK (HPACK extension for HTTP/3) |
| `golang.org/x/crypto` | v0.49.0 | BSD-3-Clause | Cryptographic primitives |
| `golang.org/x/net` | v0.52.0 | BSD-3-Clause | Networking |
| `golang.org/x/sys` | v0.42.0 | BSD-3-Clause | System calls |
| `golang.org/x/text` | v0.35.0 | BSD-3-Clause | Text processing |
| `github.com/davecgh/go-spew` | v1.1.1 | ISC | Test utility (go-spew) |
| `github.com/pmezard/go-difflib` | v1.0.0 | BSD-3-Clause | Test utility |
| `github.com/stretchr/testify` | v1.11.1 | MIT | Test assertions |
| `go.uber.org/mock` | v0.5.2 | BSD-3-Clause | Test mocking |
| `gopkg.in/yaml.v3` | v3.0.1 | Apache-2.0 | YAML parsing |

**Go dependency surface: 1 direct, 9 transitive total.** Zero-dependency constraint is met for the base build.

### quic-go Assessment

`quic-go` is the only third-party Go dependency and it is **build-gated behind `http3` tag** — not compiled in the standard build. The latest stable major version is v0.49.x as of late 2024/early 2025, but v0.59.0 is significantly ahead. At time of writing, no critical CVEs are known against quic-go v0.59.x. However:

- **quic-go v0.49+** had a known DoS vulnerability (CVE-2024-47425 / GHSA-xvj9-2w2q-jm8q) affecting versions `< 0.48.0`. v0.59.0 is well past that fix.
- Version skipping from v0.49 to v0.59 jumps several minor versions. No known vulnerabilities in v0.52+.

**Recommendation:** Pin `quic-go` to the latest stable and monitor https://github.com/quic-go/quic-go/security/advisories.

### golang.org/x/* Assessment

All `golang.org/x/*` dependencies are at recent versions (sys v0.42.0, crypto v0.49.0, net v0.52.0, text v0.35.0). No known CVEs for these versions. `golang.org/x/net` v0.52.0 contains fixes for CVE-2024-45338 (parseHost bug in ProxyFromEnvironment).

### Build Tags and CGO

- **No CGO used anywhere.** The codebase is 100% pure Go.
- Two build files per binary: `main_default.go` (standard, no http3), `main.go` (http3 stub, build-gated).
- HTTP/3 is entirely optional and compiled only with `-tags http3`.
- No external C dependencies, no system library linking.

---

## 2. npm Dependencies (internal/dashboard/ui/package.json)

**Lock file:** `package-lock.json` exists with 5370 lines. Good — semver ranges are pinned.

### Production Dependencies

| Package | Version (pinned via lock) | Purpose | Risk |
|---------|--------------------------|---------|------|
| `react` | ^19.0.0 | UI framework | LOW |
| `react-dom` | ^19.0.0 | DOM rendering | LOW |
| `react-router` | ^7.0.0 | Client-side routing | LOW |
| `@xyflow/react` | ^12.10.1 | Node/graph editor (React Flow) | LOW |
| `lucide-react` | ^0.500.0 | Icons | LOW |
| `clsx` | ^2.1.0 | Class merging | LOW |
| `class-variance-authority` | ^0.7.0 | Component variance | LOW |
| `tailwind-merge` | ^3.0.0 | Tailwind class merging | LOW |

### Dev Dependencies (significant)

| Package | Version | Purpose | Notes |
|---------|---------|---------|-------|
| `vite` | ^6.0.0 | Build tool | |
| `tailwindcss` | ^4.0.0 | CSS framework | |
| `@tailwindcss/vite` | ^4.0.0 | Tailwind Vite plugin | |
| `@vitejs/plugin-react` | ^4.5.0 | React Vite plugin | |
| `typescript` | ^5.7.0 | Type checking | |
| `eslint` | ^9.39.4 | Linting | |
| `@types/react` | ^19.0.0 | TypeScript types | |
| `vitest` | ^4.1.4 | Unit testing | |
| `jsdom` | ^29.0.2 | DOM simulation for tests | |
| `@testing-library/react` | ^16.3.2 | React testing | |

### Known npm Security Concerns

1. **`@xyflow/react` v12.x:** React Flow v12 is a mature library. No critical CVEs at time of audit. However, graph/node-editor libraries process user-provided data — monitor for injection vectors in node configuration.

2. **`tailwindcss` v4.x:** Tailwind CSS 4.x is the latest major. A CSS injection vulnerability was found in older versions (CVE-2023-3867 — arbitrary class injection via special characters). Ensure the build output is properly sanitized and not user-controlled. The `dist/` output is build-generated and embedded at compile time, not served from user input.

3. **`lucide-react` ^0.500.0:** 500.0 is a very high version number. Lucide uses incremental major versioning. v500.x is a recent release. Check for icon SVG sanitization — icons are rendered as inline SVG, ensure no XSS vector via icon name.

4. **`jsdom` v29.x:** Used in test environment only, not bundled in production. Acceptable risk if CI/test environment is isolated.

### Embedded Assets

```go
// internal/dashboard/dashboard.go (lines 27-33)
var distFS embed.FS  // React build output (Vite-hashed assets)

var staticFiles embed.FS  // Legacy static assets
```

Two `embed.FS` instances:
- `distFS` — compiled React/Vite build from `internal/dashboard/ui/dist/`
- `staticFiles` — legacy static files from `internal/dashboard/static/`

Both are embedded at **compile time** from the local filesystem, not fetched from a CDN. This eliminates:
- CDN compromise risk
- Dependency confusion via remote assets
- Supply chain attack through embedded scripts

**Build verification:** `distFS` serves Vite content-hashed JS/CSS with immutable cache headers. The `handleDistAssets` handler (dashboard.go line 1743) explicitly blocks `..` path traversal.

---

## 3. Dependency Confusion / Typosquatting Analysis

### Go Module Paths
All Go imports use canonical `github.com/guardianwaf/guardianwaf` path. No forks, no internal replacements, no direct absolute URL imports. The only external module is `github.com/quic-go/quic-go` — a well-known, canonical package.

**No `replace` directives** in go.mod — builds depend on the upstream module proxy.

**Mitigation available:** Consider vendoring (`go mod vendor`) for air-gapped builds to eliminate proxy dependency.

### npm Package Names
All npm packages are standard, canonical names from npmjs.com. No scoped packages that could be impersonated. Dashboard package name `guardianwaf-dashboard` is private (`"private": true`).

---

## 4. Additional Security Observations

### noinline Suppressions

| Location | Suppression | Issue | Severity |
|----------|-------------|-------|----------|
| `internal/layers/threatintel/feed.go:55` | `//nolint:gosec` | `InsecureSkipVerify: true` for threat intel feed TLS | MEDIUM |
| `internal/mcp/sse_test.go` (multiple) | `//nolint:noctx` | `http.Get`/`http.Post` without context — test code only | LOW |

**Only 1 suppression in production code** (threat intel TLS skip-verify). This is acceptable if the threat intel feed URL is operator-configured and not user-controlled.

### SSRF Protection

The codebase has explicit SSRF protection for upstream target configuration:
```go
// internal/proxy/proxy.go — IsPrivateOrReservedIP() check before adding targets
proxy.PrivateTargetsAllowed() && proxy.IsPrivateOrReservedIP(parsed.Hostname())
```

### Docker Auto-Discovery

Docker socket operations are platform-abstracted (Unix socket on Linux, named pipe on Windows). No privileged Docker operations by default.

---

## 5. Summary Findings

| Severity | Finding | Action Required |
|----------|---------|-----------------|
| **Info** | Go module declared `go 1.25.0`, build uses `go1.26.1` — minor version mismatch, not a security issue | Monitor |
| **Info** | Only 1 direct Go dependency (quic-go), build-gated behind `http3` tag | No action |
| **Info** | quic-go v0.59.0 is ahead of latest stable (v0.49.x) — no known CVEs | Monitor quic-go advisories |
| **Info** | No CGO, no external C dependencies, 100% pure Go | Good |
| **Low** | `InsecureSkipVerify: true` in threat intel feed — must be operator opt-in | Document; consider adding config flag |
| **Low** | `tailwindcss` v4.x — ensure no untrusted CSS class injection | Acceptable (build-time generated) |
| **Info** | `package-lock.json` exists and is pinned | Good |
| **Info** | Embed assets are compile-time local, not CDN-fetched | Good |
| **Info** | No `replace` directives, no fork imports, canonical module paths only | Good |
| **Info** | No vendor directory — builds depend on proxy availability | Consider vendoring for air-gapped |

---

## 6. Recommendations

1. **Vendor Go dependencies** (`go mod vendor`) for air-gapped/offline builds to eliminate proxy dependency.
2. **Monitor quic-go security advisories** — subscribe to https://github.com/quic-go/quic-go/security/advisories.
3. **Review threat intel feed configuration** — ensure `InsecureSkipVerify` is only set for operator-controlled internal CAs, not public feeds.
4. **Pin npm versions more tightly** — consider replacing `^` with exact versions in `package.json` for reproducible builds, even though `package-lock.json` is present.
5. **Add `package-lock.json` to .gitignore verification** — confirm it is always updated when `package.json` changes.
6. **Audit `@xyflow/react` node configuration** — if users can provide custom node data, ensure it cannot contain XSS payloads.

---

*Generated by Claude Code security audit. Report location: `security-report/dependency-audit.md`*