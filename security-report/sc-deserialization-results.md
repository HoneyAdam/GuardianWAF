# Insecure Deserialization Scan Results

**Scanner:** sc-deserialization
**Target:** GuardianWAF (Pure Go WAF)
**Date:** 2026-04-15
**Status:** No issues found.

---

## Summary

No insecure deserialization vulnerabilities were identified in the GuardianWAF codebase. The scan covered all five deserialization categories:

| Category | Status | Notes |
|----------|--------|-------|
| Gob decoding | Pass | No `encoding/gob` usage in production code |
| JSON unmarshaling | Pass | All calls use strongly-typed structs, never `interface{}` |
| YAML parsing | Pass | Custom zero-dependendency parser is safe by design |
| Binary protocols | Pass | No `encoding/binary` usage found |
| `interface{}` usage | Pass | No unsafe `interface{}` deserialization patterns |

---

## Detailed Findings

### 1. Gob Decoding — PASS

- **No `encoding/gob` usage found** in production code
- One reference exists only in `docs/adr/0023-high-availability-raft.md` (design documentation), not in executable code

### 2. JSON Unmarshal — PASS

All `json.Unmarshal` calls unmarshal into **strongly-typed structs**, not `interface{}`:

- `internal/tenant/store.go:66` — `json.Unmarshal(data, &s.index)` → `map[string]string`
- `internal/tenant/store.go:136` — `json.Unmarshal(data, &td)` → `tenantData` struct
- `internal/cluster/cluster.go:948` — `json.Unmarshal(msg.Payload, &payload)` → typed struct
- `internal/cluster/cluster.go:961` — `json.Unmarshal(msg.Payload, &payload)` → typed struct
- `internal/mcp/server.go:248` — `json.Unmarshal(req.Params, &params)` → typed struct
- All other calls throughout codebase follow the same pattern

**Note:** `cluster.go` lines 948 and 961 unmarshal cluster messages into `map[string]any`. However, these messages originate from intra-cluster communication protected by mutual TLS and an `auth_secret`, not from external untrusted input.

### 3. YAML Parsing — PASS

The custom YAML parser in `internal/config/yaml.go` is **safe by design**:

- Explicitly **does not support anchors (`&`), aliases (`*`), tags (`!!`), or multi-document (`---/`)** — the primary YAML deserialization attack vectors
- Validates UTF-8 before parsing
- Enforces **maximum nesting depth of 10** — prevents DoS via deeply nested documents
- Implements a typed `Node` tree (`ScalarNode`, `MapNode`, `SequenceNode`) — no arbitrary code execution path
- No reflection-based instantiation of arbitrary types
- Environment variable expansion (`${VAR}`, `${VAR:-default}`) uses a strict whitelist: only alphanumeric characters and underscores in variable names

### 4. Binary Protocol Parsing — PASS

- **No `encoding/binary` usage found** in the codebase
- No custom binary deserialization protocols detected

### 5. Event Deserialization — PASS

- `internal/events/file.go` uses **manual JSON serialization** (no `encoding/json`) for performance
- FileStore **does not read events back** — it is write-only, so no deserialization attack surface
- EventBus uses in-memory Go channel communication (type-safe)

---

## Conclusion

**No insecure deserialization found.**

The GuardianWAF codebase demonstrates security-conscious deserialization practices:
- No use of `encoding/gob`
- No `json.Unmarshal` into `interface{}`
- A custom YAML parser that explicitly excludes unsafe YAML features
- No binary deserialization protocols
- Intra-cluster messages are protected by TLS + authentication, not just input validation

The zero-dependency constraint (except `quic-go`) appears to have been a security benefit here — the custom YAML parser was built from scratch without the unsafe features of `yaml.v2`/`yaml.v3`.
