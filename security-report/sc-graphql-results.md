# GraphQL Security Scanner Report

**Scanner:** sc-graphql
**Target:** GuardianWAF GraphQL Security Layer
**Date:** 2026-04-16
**Path:** `internal/layers/graphql/`

---

## Executive Summary

The GuardianWAF GraphQL security implementation provides comprehensive protection against common GraphQL attacks. The layer includes depth limiting, complexity analysis, introspection blocking, alias limits, batch size controls, and directive injection detection. Overall security posture is **GOOD** with minor hardening opportunities.

---

## Security Checks

### 1. Query Depth Limits

**Status:** PASS

```
File: internal/layers/graphql/layer.go
Config: MaxDepth = 10 (default)
Protection: calculateDepth() with fragment resolution
```

The layer enforces a configurable maximum query depth (default: 10) that is checked during analysis:

```go
// layer.go:160-168
depth := calculateDepth(ast)
if depth > cfg.MaxDepth {
    issues = append(issues, Issue{
        Type:        "depth_exceeded",
        Description: fmt.Sprintf("Query depth %d exceeds maximum %d", depth, cfg.MaxDepth),
        Severity:    "high",
    })
    score += 40
}
```

Fragment spreads are properly resolved to prevent bypass via nested fragments. Depth calculation uses visited tracking to prevent infinite recursion on cyclic fragment references (`parser.go:509-511`).

**Finding:** None - depth limiting is properly implemented.

---

### 2. Query Complexity Limits

**Status:** PASS

```
File: internal/layers/graphql/layer.go
Config: MaxComplexity = 1000 (default)
Protection: calculateComplexity() scoring fields + arguments + nested selections
```

The complexity calculation accounts for:
- Each field adds 1 point
- Each argument adds 1 point
- Nested selections recursively accumulate

```go
// parser.go:540-560
func calculateSelectionComplexity(selections []Selection) int {
    complexity := 0
    for _, sel := range selections {
        if field, ok := sel.(Field); ok {
            complexity += 1          // base field
            complexity += len(field.Arguments) // arguments
            complexity += calculateSelectionComplexity(field.SelectionSet)
        }
    }
    return complexity
}
```

**Finding:** None - complexity limits are properly implemented.

---

### 3. Introspection Limits

**Status:** PASS (Secure Default)

```
File: internal/layers/graphql/layer.go
Config: BlockIntrospection = true (default)
Protection: hasIntrospection() checks for __schema, __type, __typename, etc.
```

**CRITICAL SECURITY DECISION:** The default configuration blocks introspection queries. This is the correct default for production environments as it prevents schema enumeration attacks.

```go
// layer.go:48-54
func DefaultConfig() Config {
    return Config{
        // ...
        BlockIntrospection: true, // Block schema introspection by default (VULN-008)
        // ...
    }
}
```

The `hasIntrospection()` function (`parser.go:562-579`) detects all standard introspection fields including:
- `__schema`
- `__type`
- `__typename`
- `__fields`
- `__args`
- `__inputFields`

**Finding:** None - introspection is blocked by default.

---

### 4. Directive Security

**Status:** PASS with minor concern

```
File: internal/layers/graphql/layer.go
Detection: hasDirectiveInjection() using regex patterns
Pre-compiled patterns: reDirectiveSkip, reDirectiveInclude, reDirectiveDeprecated
```

Directive injection detection uses pre-compiled regexes to identify potentially malicious directive usage:

```go
// layer.go:625-650
func hasDirectiveInjection(ast *AST) bool {
    directivePatterns := []struct {
        name    string
        pattern *regexp.Regexp
    }{
        {"skip", reDirectiveSkip},
        {"include", reDirectiveInclude},
        {"deprecated", reDirectiveDeprecated},
    }
    for _, dp := range directivePatterns {
        if strings.Contains(queryStr, "@"+dp.name) {
            if len(dp.pattern.FindAllString(queryStr, -1)) > 5 {
                return true
            }
        }
    }
}
```

**Concern:** The detection threshold (5+ occurrences) may be too permissive. A query with 3-4 directive usages would not trigger the alert, even though `@skip` and `@include` can be used to conditionally reveal fields based on variables.

**Recommendation:** Lower threshold to 3 or implement smarter detection that flags any `@skip(if: $variable)` with variable-based conditions.

---

### 5. Batch Query Attacks

**Status:** PASS

```
File: internal/layers/graphql/layer.go
Config: MaxBatchSize = 5 (default)
Protection: extractQueries() parses JSON array bodies, len(queries) checked
```

The layer properly detects and limits batch query sizes:

```go
// layer.go:99-109
if len(queries) > cfg.MaxBatchSize {
    return &Result{
        Score:   80,
        Blocked: true,
        Issues: []Issue{{
            Type:        "batch_too_large",
            Description: fmt.Sprintf("Batch size %d exceeds maximum %d", len(queries), cfg.MaxBatchSize),
        }},
    }, nil
}
```

Batch detection handles:
- JSON envelope: `{"query": "..."}`
- Batch array: `[{"query": "..."}, ...]`
- Raw GraphQL: `application/graphql` content type

**Finding:** None - batch size limits are properly enforced.

---

### 6. Field Suggestion / Enumeration

**Status:** PASS

The `BlockIntrospection: true` default prevents field enumeration via GraphQL's built-in introspection system. This blocks:
- Schema discovery via `__schema { types { ... } }`
- Field discovery via `__type(name: "...") { fields { ... } }`
- Type relationships via `__typename`

**Finding:** None - schema enumeration is prevented.

---

### 7. Parser Security (DoS Prevention)

**Status:** PASS

```
File: internal/layers/graphql/parser.go
Protections:
  - maxParseDepth = 256 (stack overflow prevention)
  - maxQueryLength = 256KB (memory allocation limit)
```

The parser implements two critical DoS protections:

```go
// parser.go:133-140
const maxParseDepth = 256 // Prevents stack overflow from deeply nested queries

const maxQueryLength = 256 * 1024 // 256KB max query string size
```

Parser depth is tracked in `parseSelectionSetDepth()` and `parseFieldDepth()` with depth limit checking at every recursion level (`parser.go:253-254`).

**Finding:** None - parser has proper DoS protections.

---

## Configuration Analysis

### Default Configuration (layer.go:49-58)

```go
func DefaultConfig() Config {
    return Config{
        Enabled:            true,
        MaxDepth:           10,
        MaxComplexity:      1000,
        BlockIntrospection: true, // SECURE DEFAULT
        AllowListEnabled:   false,
        MaxAliases:         10,
        MaxBatchSize:       5,
    }
}
```

### Pipeline Registration (main.go:2571-2584)

```go
if cfg.WAF.GraphQL.Enabled {
    graphqlLayer := graphql.NewLayer(graphql.Config{
        Enabled:            cfg.WAF.GraphQL.Enabled,
        MaxDepth:           cfg.WAF.GraphQL.MaxDepth,
        MaxComplexity:      cfg.WAF.GraphQL.MaxComplexity,
        BlockIntrospection: gqlCfg.BlockIntrospection,
        MaxAliases:         10,
        MaxBatchSize:       5,
    })
    eng.AddLayer(engine.OrderedLayer{Layer: graphqlLayer, Order: engine.OrderGraphQL})
}
```

Layer order is 285, positioned between API Validation (280) and Sanitizer (300).

---

## Findings Summary

| Check | Status | Severity | Notes |
|-------|--------|----------|-------|
| Query Depth Limits | PASS | - | Default 10, configurable |
| Query Complexity | PASS | - | Default 1000, scoring-based |
| Introspection | PASS | - | Blocked by default (secure) |
| Directive Injection | PASS | Low | Threshold of 5 may be lenient |
| Batch Attacks | PASS | - | MaxBatchSize=5 enforced |
| Field Enumeration | PASS | - | Prevented via introspection block |
| Parser DoS | PASS | - | 256 depth limit, 256KB size limit |

---

## Recommendations

1. **Directive injection threshold:** Consider lowering the threshold from 5 to 3 for `@skip`/`@include` directives, or add detection for variable-based conditional directives (`@skip(if: $var)`).

2. **Alias limit documentation:** The `MaxAliases` config (default 10) is set but not exposed as a documented security setting in the default config. Consider adding it to the config struct comment.

3. **Operation name tracking:** The parser extracts operation names but does not include them in the AST's `Operation` struct (see `parser.go:227-237`). For audit purposes, consider capturing the operation name for logging/security events.

4. **Rate limiting integration:** Consider adding GraphQL-specific rate limiting based on query complexity score, not just batch count.

---

## Test Coverage

Tests exist in `internal/layers/graphql/layer_test.go`:
- `TestIsGraphQLRequest` - path and content-type detection
- `TestCalculateDepth` - depth calculation with fragment resolution
- `TestCalculateComplexity` - complexity scoring
- `TestHasIntrospection` - introspection field detection
- `TestLayer_Analyze` - full analysis pipeline with scoring
- `TestParseQuery` - parser correctness

**Gap:** No tests for directive injection detection, batch size limits, or malformed query handling.

---

## Conclusion

GuardianWAF's GraphQL security layer provides solid protection against the OWASP GraphQL Top 10 risks. The secure default of blocking introspection is particularly commendable. The implementation correctly handles fragment resolution, batch attacks, and parser-level DoS protection.

**Overall Assessment:** SECURE with minor hardening opportunities