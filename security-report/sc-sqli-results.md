# SQL Injection Security Scan Results

**Scanner:** sc-sqli
**Date:** 2026-04-16
**Target:** github.com/guardianwaf/guardianwaf
**Go Version:** 1.25.0

---

## Executive Summary

**0 vulnerabilities found.**

GuardianWAF is a zero-dependency Web Application Firewall that does not use a SQL database. All data persistence is handled through:
- **In-memory ring buffers** (event storage)
- **File-based JSON storage** (tenant data, rotated event logs)
- **Redis backend** (optional external cache, using RESP protocol)

No SQL query construction, ORM patterns, or database drivers are present in the codebase. The only "query-like" operations are in-memory filter operations on Go structs.

---

## Scope

| Component | Type | Status |
|-----------|------|--------|
| `internal/layers/detection/sqli/` | WAF detection logic | Reviewed - not a database |
| `internal/events/storage.go` | EventStore interface | Reviewed - no SQL |
| `internal/events/memory.go` | In-memory ring buffer | Reviewed - no SQL |
| `internal/events/file.go` | JSONL file storage | Reviewed - no SQL |
| `internal/discovery/storage.go` | MemoryStorage | Reviewed - no SQL |
| `internal/tenant/store.go` | JSON file store | Reviewed - no SQL |
| `internal/layers/cache/redis.go` | Redis RESP client | Reviewed - safe |
| `internal/layers/rules/rules.go` | Rule engine | Reviewed - no SQL |
| `internal/layers/crs/parser.go` | ModSecurity CRS parser | Reviewed - no SQL |
| `internal/layers/siem/exporter.go` | SIEM exporter | Reviewed - no SQL |

---

## Analysis Details

### 1. SQL Detection Layer (`internal/layers/detection/sqli/`)

The `sqli/` package is the WAF's own SQL injection detector. It uses tokenization and pattern matching against HTTP request data to detect SQL injection attacks. It does not perform any SQL queries.

- `sqli.go` - Detection logic using token analysis (union, boolean, time-based, stacked queries)
- `patterns.go` - Attack pattern definitions
- `tokenizer.go` - SQL-aware tokenizer

**Finding:** This is protection logic, not SQL query building. No vulnerability.

### 2. Event Storage (`internal/events/`)

**`memory.go`** - In-memory ring buffer with `Query(filter EventFilter)` method. Filtering is performed via struct field comparisons:

```go
func (ms *MemoryStore) matchesFilter(ev engine.Event, f EventFilter) bool {
    if !f.Since.IsZero() && ev.Timestamp.Before(f.Since) { return false }
    if f.ClientIP != "" && ev.ClientIP != f.ClientIP { return false }
    if f.Path != "" && !strings.HasPrefix(ev.Path, f.Path) { return false }
    // ...
}
```

**`file.go`** - JSONL file writer. Events are written as one JSON object per line. No query support (`Query` returns error).

**Finding:** Pure in-memory/file-based. No SQL. No vulnerability.

### 3. Tenant Store (`internal/tenant/store.go`)

JSON file-based tenant storage with atomic writes (temp file + rename). No SQL database.

```go
func (s *Store) LoadTenant(tenantID string) (*Tenant, error) {
    if !safeTenantID(tenantID) {
        return nil, fmt.Errorf("invalid tenant ID")
    }
    // Reads from JSON file, not SQL
}
```

`safeTenantID()` validates tenant IDs contain only `[a-zA-Z0-9_-]`, preventing path traversal.

**Finding:** File-based JSON, not SQL. No vulnerability.

### 4. Redis Backend (`internal/layers/cache/redis.go`)

Zero-dependency Redis client using RESP protocol. Commands are built using bulk string encoding which prevents RESP injection:

```go
func (rb *RedisBackend) sendCommand(args ...string) error {
    cmd := fmt.Sprintf("*%d\r\n", len(args))
    for _, arg := range args {
        cmd += fmt.Sprintf("$%d\r\n%s\r\n", len(arg), arg)  // Bulk string encoding
    }
    // ...
}
```

`Set()` validates values do not contain `\r\n`:
```go
if bytes.ContainsAny(value, "\r\n") {
    return fmt.Errorf("cache value contains illegal \\r\\n characters")
}
```

All `sendCommand` call sites use hardcoded command names (`GET`, `SET`, `DEL`, `EXISTS`, `KEYS`, `FLUSHDB`, `AUTH`, `SELECT`). Keys/values originate from internal WAF state (request paths, IP addresses, JSON-encoded events), not direct HTTP user input. The `KEYS` pattern in `InvalidatePath` is constructed as `*:<path>:*` programmatically, not from HTTP input.

**Finding:** RESP protocol properly encodes arguments. All call paths are internal. No vulnerability.

### 5. Rule Engine (`internal/layers/rules/rules.go`)

Custom WAF rule engine with conditions (field + operator + value). Conditions are evaluated against request context using string matching and regex. No SQL query construction.

Operators: `equals`, `contains`, `matches`, `in_cidr`, `greater_than`, `less_than`. Regex patterns are validated for complexity (max nesting depth 6) and executed with timeout and concurrency limits.

**Finding:** In-memory condition evaluation, not SQL. No vulnerability.

### 6. SIEM Exporter (`internal/layers/siem/exporter.go`)

Security events are exported to external SIEM systems (Splunk, Elastic, CEF, LEF). Uses standard HTTP POST with JSON body. SSRF protections via DNS resolution validation and private IP blocking.

**Finding:** HTTP-based export, not SQL. No vulnerability.

### 7. CRS Parser (`internal/layers/crs/parser.go`)

Parses ModSecurity Core Rule Set SecRule directives. Input is the CRS rule files (static configuration), not HTTP user input. No SQL query construction.

**Finding:** Config file parser, not SQL. No vulnerability.

---

## Conclusion

GuardianWAF is a reverse-proxy WAF with no SQL database dependency. All storage uses either in-memory Go data structures, JSON files, or Redis (with RESP protocol). There is no SQL query building, no ORM usage, and no database drivers present in the codebase.

**CWE-89 (SQL Injection) - Not Applicable**

The project constraint of **zero external Go dependencies** (only `quic-go` for optional HTTP/3) ensures no ORM or database driver libraries can be introduced.

---

## Recommendations

None required. No SQL injection vulnerabilities were identified.
