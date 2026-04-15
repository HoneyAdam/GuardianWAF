# Command Injection Security Scan Results

**Target:** Pure Go WAF codebase (GuardianWAF)
**Scanner:** sc-cmdi (Command Injection)
**Date:** 2026-04-15

## Executive Summary

**No command injection vulnerabilities found.**

## Scan Scope

Searched for:
1. `exec.Command` with shell invocation (`sh -c`, `bash -c`, etc.)
2. Shell metacharacters in command arguments
3. User input reaching external command execution
4. Shell operators (`;`, `|`, `&&`, `||`) in command contexts

## Detailed Findings

### Codebase Analysis

#### exec.Command Usage

| Location | Lines | Purpose | Risk |
|----------|-------|---------|------|
| `internal/docker/client.go` | 270, 321 | Docker CLI invocation | **Safe** - args built from internal config |
| `cmd/guardianwaf/main_test.go` | 603-842 | Test binary execution | **Safe** - hardcoded test strings only |

#### internal/docker/client.go Analysis

The Docker client uses `exec.CommandContext(ctx, "docker", args...)` in two locations:

1. **Line 270** (`WatchEvents`): Builds args from:
   - `c.hostFlag` (configured via `NewClient`/`NewTLSClient`)
   - `c.tlsVerify` (boolean flag)
   - `c.certPath` (configured TLS path)

2. **Line 321** (`dockerCmd`): Builds args from the same internal configuration fields.

All args are **internal configuration values**, NOT user-provided HTTP request data.

#### cmd/guardianwaf/main_test.go Analysis

All `exec.Command` calls use **hardcoded strings**:
- `exec.Command("go", "build", "-o", binPath, ".")`
- `exec.Command(bin, "version")`
- `exec.Command(bin, "validate", "-config", cfgPath)`

These are test-only and do not handle external input.

### Shell Invocation Check

| Pattern | Found |
|---------|-------|
| `exec.Command(... "sh", "-c", ...)` | No |
| `exec.Command(... "bash", "-c", ...)` | No |
| `exec.Command(... "cmd.exe", ...)` | No |
| `exec.Command(... "powershell", ...)` | No |

### Shell Metacharacter Check

| Pattern | Found in Command Execution |
|---------|---------------------------|
| `;` passed to shell | No |
| `\|` in command args | No |
| `&&` in command args | No |
| `$(...)` subshell | No |
| Backtick execution | No |

### Detection Layer (Not Vulnerable)

GuardianWAF includes a **command injection detector** (`internal/layers/detection/cmdi/`) that:
- Detects shell metacharacters (`;`, `|`, `&&`, `||`, backticks, `$()`)
- Identifies shell interpreter paths (`/bin/sh`, `/bin/bash`, `cmd`, `powershell`)
- Scores requests containing these patterns (40-100 based on severity)

This is **defensive code**, not vulnerable execution.

## Conclusion

**No command injection vulnerabilities found.**

The codebase does not invoke external shell commands with user-controlled input. All `exec.Command` usage:
1. Calls Docker CLI with internal configuration (not HTTP request data)
2. Uses hardcoded strings in test code only

The WAF correctly **detects and blocks** command injection attempts in incoming requests via its cmdi detector layer.
