# NoSQL Injection Security Report

**Scanner:** sc-nosqli
**Target:** GuardianWAF (Go WAF Engine)
**Date:** 2026-04-16
**Severity Scale:** Critical | High | Medium | Low

---

## Executive Summary

GuardianWAF uses in-memory storage for request processing, JSON files for event persistence, and optional Redis for distributed caching. The codebase does not use MongoDB, CouchDB, Elasticsearch, or any document-store NoSQL database. Therefore, traditional NoSQL injection vectors (operator injection in MongoDB queries, JavaScript injection via `$where`, etc.) are **not applicable**.

However, several areas were reviewed for potential injection-like vulnerabilities in the storage and data handling layers:

- **Event storage** (`internal/events/file.go`, `internal/events/memory.go`) — JSON serialization uses a custom manual builder (not `encoding/json`), immune to `json.Unmarshal` manipulation.
- **Tenant store** (`internal/tenant/store.go`) — JSON file storage with validation. Tenant IDs are validated via `safeTenantID()` before file I/O.
- **Redis backend** (`internal/layers/cache/redis.go`) — Uses RESP protocol with bulk strings; values containing `\r\n` are rejected.
- **Discovery storage** (`internal/discovery/storage.go`) — Pure in-memory; no external input.
- **YAML parser** (`internal/config/yaml.go`) — Custom parser, explicitly does not support `!!` tags (safe from arbitrary type unmarshaling).
- **Client reports** (`internal/layers/clientside/report_handler.go`) — JSON unmarshal into typed struct with `map[string]any` Data field; stored in-memory only.
- **API validation** (`internal/layers/apivalidation/layer.go`) — Uses `any` for JSON body parsing but validates against OpenAPI schema.
- **MCP handlers** (`internal/mcp/handlers.go`) — Structured JSON params with typed structs.

**No exploitable NoSQL injection vulnerabilities were found.** The architecture uses a defense-in-depth approach with input validation, type safety, and protocol-level protections.

---

## Detailed Findings

### Finding: NOSQLI-001 — Client Report JSON Unmarshal into map[string]any

**Severity:** Low
**Confidence:** 40
**File:** `internal/layers/clientside/report_handler.go:16`
**Vulnerability Type:** CWE-943 (Improper Neutralization of Special Elements in Data Query Logic)

**Description:**

The `ClientReport` struct contains a `Data map[string]any` field:

```go
type ClientReport struct {
    Type string         `json:"type"`
    Data map[string]any `json:"data"`
    URL  string         `json:"url"`
    TS   int64          `json:"ts"`
}
```

While the top-level struct is typed, the `Data` field allows any JSON value including nested maps and arrays. This data comes from HTTP POST requests to the `/_guardian/report` endpoint.

**Proof of Concept:**

```json
// Attacker sends JSON with complex nested structure:
{
    "type": "custom",
    "data": {
        "nested": {"deeper": [1, 2, 3]}
    },
    "url": "http://evil.com",
    "ts": 1234567890
}
```

**Impact:** Limited to in-memory storage. The reports are stored in a slice with max 1000 entries. No downstream database queries are made with this data. The data is served via `Reports()` method which returns the stored reports.

**Remediation:** Consider defining specific typed fields for `Data` if the report structure is known, or validate the unmarshaled data structure before storage.

**References:**
- https://cwe.mitre.org/data/definitions/943.html
- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection

---

### Finding: NOSQLI-002 — API Validation Layer Uses any for JSON Parsing

**Severity:** Info
**Confidence:** 20
**File:** `internal/layers/apivalidation/layer.go:604-605`

**Description:**

The API validation layer parses JSON request bodies into `any`:

```go
case "application/json":
    var data any
    if err := json.Unmarshal(ctx.Body, &data); err != nil {
        findings = append(findings, engine.Finding{...})
        return findings
    }

    result := validator.Validate(data, route.BodySchema.Schema, "body")
```

This is followed by schema validation using the custom `SchemaValidator.Validate()` method which validates against OpenAPI specs.

**Assessment:** This is safe because:
1. The JSON is immediately validated against a predefined OpenAPI schema
2. The schema enforces type constraints and additionalProperties rules
3. No data is passed to any database query

**References:**
- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection

---

### Finding: NOSQLI-003 — Tenant ID Validation Uses Allowlist

**Severity:** Info
**Confidence:** 30
**File:** `internal/tenant/store.go:24`

**Description:**

The `safeTenantID` function uses an allowlist approach (alphanumeric, `-`, `_`):

```go
func safeTenantID(id string) bool {
    if len(id) == 0 || len(id) > 128 {
        return false
    }
    for _, c := range id {
        switch {
        case c >= '0' && c <= '9':
        case c >= 'a' && c <= 'z':
        case c >= 'A' && c <= 'Z':
        case c == '-' || c == '_':
        default:
            return false
        }
    }
    return true
}
```

**Assessment:** This is a good security practice. The validation is applied at the API boundary (`LoadTenant`, `DeleteTenant`). The JSON file read in `LoadAllTenants` processes files discovered via directory listing, but the directory is created with `0o700` permissions.

**References:**
- https://cwe.mitre.org/data/definitions/943.html

---

## Architecture Analysis

### Why NoSQL Injection is Not Applicable

GuardianWAF's storage architecture:

1. **In-memory processing** — HTTP requests are processed in-memory with `sync.Pool` for zero-allocation hot paths. No query building occurs against a NoSQL database.

2. **Event storage** — Events are serialized using a custom `marshalEventJSON` function that manually builds JSON strings. This avoids `encoding/json` entirely and cannot be manipulated via JSON injection.

3. **Redis cache** — The Redis backend uses RESP protocol with bulk strings:
   - Keys and values are sent as bulk strings (prefixed with `$len\r\n`)
   - Values containing `\r\n` are explicitly rejected in `Set()`:
   ```go
   if bytes.ContainsAny(value, "\r\n") {
       return fmt.Errorf("cache value contains illegal \\r\\n characters")
   }
   ```
   - Commands are built using bulk string encoding, preventing RESP injection.

4. **YAML parser** — The custom YAML parser explicitly does not support:
   - Anchors (`&`) and aliases (`*`)
   - Tags (`!!type`)
   - Multi-document markers (`---`)
   
   From `yaml.go:4`:
   ```go
   // It does NOT support anchors (&), aliases (*), tags (!!), or multi-document (---/...).
   ```

5. **No MongoDB/CouchDB/Elasticsearch** — The codebase contains no imports or usage of these databases.

### Storage Components Reviewed

| Component | File(s) | Pattern | Assessment |
|-----------|---------|---------|------------|
| Event FileStore | `internal/events/file.go` | Custom JSON builder | Safe — no `json.Unmarshal` |
| Event MemoryStore | `internal/events/memory.go` | In-memory ring buffer | Safe — typed Go structs |
| Tenant Store | `internal/tenant/store.go` | File JSON + safeTenantID | Safe — allowlist validation |
| Discovery Storage | `internal/discovery/storage.go` | In-memory only | Safe — no external input |
| Redis Backend | `internal/layers/cache/redis.go` | RESP bulk strings | Safe — RESP injection blocked |
| AI Store | `internal/ai/store.go` | Typed struct JSON | Safe — typed struct unmarshaling |
| Client Reports | `internal/layers/clientside/report_handler.go` | Typed struct with `any` Data | Low risk — in-memory only |
| API Validation | `internal/layers/apivalidation/layer.go` | `any` + schema validation | Safe — validated against schema |
| GraphQL Layer | `internal/layers/graphql/layer.go` | Typed struct extraction | Safe — only Query field extracted |
| YAML Parser | `internal/config/yaml.go` | Custom, no `!!` tags | Safe — no arbitrary type unmarshaling |
| MCP Handlers | `internal/mcp/handlers.go` | Typed struct params | Safe — structured input |
| Cluster Messages | `internal/cluster/cluster.go` | `json.RawMessage` payloads | Safe — typed struct unmarshaling |
| Dashboard API | `internal/dashboard/dashboard.go` | `limitedDecodeJSON` | Safe — typed struct decoding |

---

## Conclusion

GuardianWAF does not use NoSQL databases in a manner that would make it vulnerable to NoSQL injection attacks. The storage layers are well-protected:

- Custom JSON serialization avoids `json.Unmarshal` risks in event storage
- Redis uses RESP protocol with bulk strings and delimiter validation
- YAML parser explicitly excludes dangerous tags (`!!type`)
- Tenant store has allowlist validation on IDs
- All JSON unmarshaling uses typed Go structs (except API validation which has schema validation)

The only areas with any notable patterns are:
1. Client report `Data map[string]any` field — low severity due to in-memory-only storage
2. API validation `any` parsing — safe due to schema validation

**Overall Assessment: No significant NoSQL injection vulnerabilities found.**

---

## References

- [OWASP NoSQL Injection Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection)
- [CWE-943: Improper Neutralization of Special Elements in Data Query Logic](https://cwe.mitre.org/data/definitions/943.html)
- [NoSQL Injection Cheat Sheet](https://www.netsparker.com/blog/web-security/nosql-injection-cheat-sheet/)

---

*Generated by sc-nosqli scanner for GuardianWAF*
