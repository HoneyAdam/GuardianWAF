# ADR 002: Custom YAML Parser

## Status: Accepted

## Context

GuardianWAF needs to parse complex YAML configuration files with features like variable substitution, includes, and deep merging. Standard YAML libraries (gopkg.in/yaml.v3) use struct tags which couple parsing to data structures and limit flexibility.

## Decision

Implement a custom YAML parser using the Go stdlib `text/scanner` and YAML node tree manipulation. Configuration is loaded into a generic node tree, then mapped to typed structs.

## Consequences

**Positive:**
- No external dependency for YAML parsing
- Supports advanced features: environment variable substitution (`${VAR}`), includes, defaults layering
- Decouples file format from internal data structures
- Hot-reload can diff node trees efficiently

**Negative:**
- Custom parser must handle YAML spec edge cases
- More code to maintain (~1500 lines for the parser)
- No community bug fixes

## Alternatives Considered

- `gopkg.in/yaml.v3` with struct tags — rejected due to ADR 001
- JSON-only configuration — less human-friendly for complex configs
