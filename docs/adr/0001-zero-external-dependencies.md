# ADR 001: Zero External Go Dependencies

## Status: Accepted

## Context

GuardianWAF is a Web Application Firewall that needs to be auditable, secure, and easy to deploy. Go's standard library provides most networking, crypto, and HTTP functionality built-in.

## Decision

GuardianWAF will use zero external Go dependencies. The only exception is `quic-go` for HTTP/3 support (optional, behind a build tag).

## Consequences

**Positive:**
- Supply chain attack surface minimized to near zero
- No dependency version conflicts or breaking updates
- Binary is statically linked with known code
- Faster builds, smaller binary
- Full code audit feasible (only stdlib + own code)

**Negative:**
- Must implement some functionality that libraries provide (YAML parsing, JWT validation, CRS rule parsing)
- No access to ecosystem improvements without manual implementation
- More upfront development time

## Alternatives Considered

- Using standard libraries (gopkg.in/yaml.v3, golang-jwt) — rejected due to dependency chain
- Vendoring specific libraries — adds maintenance burden without eliminating risk
