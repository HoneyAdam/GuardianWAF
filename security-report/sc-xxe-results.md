# SC-XXE: XML External Entity Scanner Results

**Scanner:** sc-xxe
**Target:** `D:/CODEBOX/PROJECTS/GuardianWAF`
**Date:** 2026-04-16

---

## Summary

| Category | Result |
|----------|--------|
| XXE Vulnerabilities Found | 0 |
| XXE Detector Coverage | Pattern-based (signature matching) |
| Actual XML Parsing Code | None found |
| SAML Parsing | None found |
| SOAP Parsing | None found |
| SVG/XLSX/DOCX Processing | None found |

---

## Phase 1: Discovery

### Files Scanned

- `internal/layers/detection/xxe/` — XXE detector implementation
- All Go source files (`**/*.go`)
- Configuration files and documentation

### Search Results

No usage of Go's `encoding/xml` package was found anywhere in the codebase. The following patterns were all absent:

```
encoding/xml, xml.NewDecoder, xml.Unmarshal, xml.Decode,
Decoder{}, NewParser (XML-related), DocumentBuilder,
SAXParser, XMLReader, XMLElement
```

### Threat Intel Feeds

Threat intel feeds (`internal/layers/threatintel/feed.go`) only support JSON, JSONL, and CSV formats. No XML feed parsing is implemented.

### GraphQL Layer

The GraphQL layer (`internal/layers/graphql/parser.go`) uses a custom parser. No XML parsing code was found.

---

## Phase 2: Analysis

### XXE Detector (`internal/layers/detection/xxe/xxe.go`)

The XXE detector is a **pattern-based (signature-based) detector**, not a real XML parser. It works by scanning request body, query parameters, and headers for malicious string patterns.

**Detection methods:**
- String matching for DOCTYPE declarations (`<!DOCTYPE`, `<!doctype`)
- String matching for ENTITY declarations (`<!ENTITY`)
- Pattern matching for SYSTEM keyword with dangerous protocols (`file://`, `http://`, `https://`, `expect://`, `php://`)
- Parameter entity detection (`<!ENTITY %`)
- XInclude detection (`<xi:include`)
- SSI include detection (`<!--#include`)
- CDATA section inspection for suspicious content

**Supported content types:**
- `application/xml`, `text/xml`
- `application/soap+xml`
- `application/rss+xml`
- `application/xhtml+xml`
- Plus heuristic detection for bodies starting with `<?xml` or `<!DOCTYPE`

### Why No True XXE Vulnerabilities Exist

Go's `encoding/xml` package is not used anywhere in the codebase. The WAF itself does not parse XML documents — it only inspects HTTP traffic for attack patterns. This means:

1. The WAF cannot be exploited via XXE attacks targeting its own processing
2. There is no XML parser configuration to harden against XXE
3. The XXE detector serves to protect **back-end services** that process XML

### Known Limitation

The pattern-based detector cannot catch all XXE variants. It will not detect:
- Entity expansion attacks (billion laughs) where the entity name doesn't contain obvious keywords
- XXE via XML comment manipulation
- XXE using alternative encoding (UTF-7, UTF-16, etc.)
- Blind XXE where the payload uses unusual formatting to evade string matching

---

## Findings

### No Vulnerabilities Found

No XXE vulnerabilities were identified in the GuardianWAF codebase.

**Reason:** The codebase does not contain any XML parsing code that could process external entities. The XXE detector is a WAF layer that detects XXE attack patterns in HTTP traffic — it is not itself an XML parser.

---

## Recommendations

1. **Continue pattern-based detection** — The current signature-based approach is appropriate for a WAF layer that inspects traffic, not parses XML.

2. **Consider regex-based entity expansion detection** — Add detection for nested entity expansion patterns like `&lol;&lol;...` to catch billion laughs variants.

3. **Add encoded XML detection** — Consider adding detection for UTF-7 (`+ADw-` for `<`) and UTF-16 encoded XML to catch encoding-based bypasses.

4. **No remediation needed** for the codebase itself — there is no XML parsing code to harden.

---

## References

- CWE-611: Improper Restriction of XML External Entity Reference (https://cwe.mitre.org/data/definitions/611.html)
- OWASP Top 10 2021: A05:2021 Security Misconfiguration
- Go `encoding/xml` Security Notes (https://pkg.go.dev/encoding/xml): Go's `xml.Decoder` does not resolve external entities by default, but any code using it should still be audited for XXE if DTD processing is enabled.
