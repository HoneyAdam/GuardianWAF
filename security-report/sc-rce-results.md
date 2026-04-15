# RCE Security Scan Results - GuardianWAF

**Scan Date:** 2026-04-15
**Target:** Pure Go WAF codebase
**Tool:** sc-rce skill

---

## Results: No Remote Code Execution Vulnerabilities Found

The codebase does not contain any dynamic code execution vectors that could lead to remote code execution.

---

## Scanned Categories

| Category | Status |
|----------|--------|
| Go plugin loading (`plugin.Open`) | Not present |
| Embedded interpreters (`yaegi`, etc.) | Not present |
| `go/ast` evaluation | Not present |
| Template execution (`text/template`) | Not present |
| Script engines / VM runners | Not present |
| `os/exec` with user input | Not vulnerable |
| Dynamic expression evaluation | Not present |

---

## Key Code Locations Analyzed

### exec.Command Usage
All `exec.Command` calls use hardcoded argument arrays with no user input concatenation:

- `internal/docker/client.go:270,321` - Docker CLI arguments are hardcoded string slices
- Test files - Only use hardcoded binary paths

### Rule Evaluation Layers
- `internal/layers/rules/rules.go` - Static operators only (regex, string matching, numeric comparison)
- `internal/layers/crs/operators.go` - Uses `regexp.Regexp` with timeout-wrapped matching

### ML Layer
- `internal/ml/onnx/model.go` - POC stub, no actual ONNX runtime or dynamic code

### Detection Engines
- `internal/layers/detection/*` - Pattern-matching detection only (SQLi, XSS, LFI, CMDi, XXE, SSRF)

---

## Notes

- The WAF enforces a zero-dependency constraint (pure Go standard library + optional `quic-go`)
- All rule matching is static string/regex operations — no dynamic expression parsing
- Pipeline layers use structured data only, no eval-style evaluation