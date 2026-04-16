# Command Injection (CMDi) Security Scan Results

**Scanner:** sc-cmdi (OS Command Injection)
**Date:** 2026-04-16
**Project:** GuardianWAF
**Files Scanned:** Full codebase

---

## Executive Summary

**Vulnerabilities Found:** 0
**False Positives (Legitimate Uses):** 3

The codebase has **no command injection vulnerabilities**. All `exec.Command` usage is protected by input validation and does not involve shell execution with user-controlled input.

---

## Detailed Findings

### FALSE POSITIVE 1 — Test Suite (Non-Runtime)

**File:** `cmd/guardianwaf/main_test.go:603`
```go
cmd := exec.Command("go", "build", "-o", binPath, ".")
```
**Analysis:** Test harness executing a hardcoded `go build` command with a constructed binary path. No user input involved. This is a build script, not a runtime attack surface.

**Verdict:** False Positive — Internal tooling, not reachable from attacker-controlled input.

---

### FALSE POSITIVE 2 — Docker Client (Internal Orchestration)

**File:** `internal/docker/client.go:270`
```go
cmd := exec.CommandContext(ctx, "docker", args...)
```
**File:** `internal/docker/client.go:321`
```go
cmd := exec.CommandContext(ctx, "docker", args...)
```
**Analysis:** These calls invoke the Docker CLI with arguments constructed from:
1. `StreamEvents()` — uses a hardcoded filter string and fixed docker subcommands (`events`, `--filter`, `--format`)
2. `dockerCmd()` — assembles args from internal `hostFlag`, `tlsVerify`, `certPath` fields, plus user-supplied args that are validated by `isSafeContainerRef()`

The `isSafeContainerRef()` function (lines 356-374) validates all container IDs/names passed to docker commands, rejecting any character outside `[0-9a-zA-Z\-_.]` — blocking all shell metacharacters (`;`, `&`, `$`, `|`, etc.).

**Verdict:** False Positive — Protected by `isSafeContainerRef()` validation and internal-only argument construction. The `labelPrefix` parameter comes from config, not HTTP request input.

---

### FALSE POSITIVE 3 — ACME Client (Pure HTTP/No Shell)

**File:** `internal/acme/client.go`
**Analysis:** The ACME client implements RFC 8555 (Let's Encrypt) entirely over HTTP/S. All certificate operations (account registration, HTTP-01 challenges, certificate issuance) use `crypto/x509`, `net/http`, and JWS signing. Zero shell execution.

**Verdict:** False Positive — Pure cryptographic/HTTP operations, no command execution.

---

## Protection Mechanisms Observed

### 1. Input Validation in Docker Client
The `isSafeContainerRef()` function at `internal/docker/client.go:356-374` provides a defense-in-depth allowlist for all container references:

```go
func isSafeContainerRef(id string) bool {
    if len(id) == 0 || len(id) > 128 {
        return false
    }
    for _, c := range id {
        switch {
        case c >= '0' && c <= '9':
        case c >= 'a' && c <= 'z':
        case c >= 'A' && c <= 'Z':
        case c == '-' || c == '_' || c == '.':
        default:
            return false
        }
    }
    return true
}
```

This blocks all shell metacharacters: `;`, `&`, `|`, `$`, `` ` ``, `(`, `)`, `>`, `<`, `\`.

### 2. Command Injection Detection Layer
The codebase includes a comprehensive CMDi detector at `internal/layers/detection/cmdi/` that scans for:
- Shell metacharacters (`;`, `&&`, `||`, `|`)
- Command substitution (`$(...)`, backticks)
- Shell interpreter paths (`/bin/sh`, `/bin/bash`, etc.)
- Interpreter execution flags (`python -c`, `perl -e`, etc.)
- Base64 pipe chains (`base64 -d | sh`)
- Encoded newline injection (`%0a`, `%0d`)

### 3. Zero Shell Execution Policy
The ACME, proxy, and all WAF layers use pure Go standard library calls. No shell=True or `/bin/sh -c` patterns exist in the codebase (beyond test data for the detector).

---

## Recommendations

**No remediation required.** The codebase demonstrates sound security practices for command execution:
- Uses array-form `exec.Command` (not shell string interpolation)
- Docker client validates all external container references
- Command injection detector provides defense-in-depth

---

## References

- CWE-78: https://cwe.mitre.org/data/definitions/78.html
- OWASP: Command Injection
- Go exec package: https://pkg.go.dev/os/exec
