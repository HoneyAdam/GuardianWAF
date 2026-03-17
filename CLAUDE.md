# GuardianWAF — Claude Code Instructions

## Project Overview
GuardianWAF is a zero-dependency Web Application Firewall written in Go.
Module: `github.com/guardianwaf/guardianwaf`

## Key Constraints
- **ZERO external dependencies** — only Go stdlib. No exceptions.
- Use `any` instead of `interface{}`
- Use built-in `min`/`max` functions (Go 1.21+)
- Use `range N` for simple loops (Go 1.22+)
- Use `slices.Contains` where applicable

## Build & Test
```bash
make build          # Build binary
make test           # Run all tests with -race
make lint           # Run golangci-lint
make bench          # Run benchmarks
make cover          # Generate coverage report
go test ./...       # Quick test all packages
go vet ./...        # Vet all packages
```

## Architecture
6-layer pipeline executed in order:
1. IP ACL (100) — radix tree CIDR matching
2. Rate Limit (200) — token bucket per IP/path
3. Sanitizer (300) — normalize + validate requests
4. Detection (400) — 6 detectors: sqli, xss, lfi, cmdi, xxe, ssrf
5. Bot Detection (500) — JA3, UA, behavioral analysis
6. Response (600) — security headers, data masking

## Package Layout
- `cmd/guardianwaf/` — CLI (serve, sidecar, check, validate)
- `internal/engine/` — Core engine, pipeline, scoring, context
- `internal/config/` — Custom YAML parser, config structs, validation
- `internal/layers/` — All WAF layers (ipacl, ratelimit, sanitizer, detection/*, botdetect, response)
- `internal/proxy/` — Reverse proxy, load balancer, circuit breaker
- `internal/tls/` — TLS manager, ACME, SNI
- `internal/dashboard/` — Web UI, REST API, SSE
- `internal/mcp/` — MCP JSON-RPC server (15 tools)
- `internal/events/` — Event storage (memory ring buffer, JSONL file)
- `guardianwaf.go` + `options.go` — Public library API

## Scoring System
- Each detector produces scores 0-100
- Scores accumulate per-request
- block_threshold: 50 (default), log_threshold: 25
- Per-detector multipliers adjust sensitivity

## CLI Commands
```
guardianwaf serve     # Standalone reverse proxy (full features)
guardianwaf sidecar   # Lightweight proxy (no dashboard/MCP)
guardianwaf check     # Dry-run request test
guardianwaf validate  # Config validation
```
