# SC-FILE-UPLOAD: Insecure File Upload Report

**Scanner:** sc-file-upload v1.0.0
**Target:** GuardianWAF File Upload Handlers
**Date:** 2026-04-16
**Severity Classification:** Critical | High | Medium | Low

---

## Summary

| Category | Finding | Severity | Confidence |
|----------|---------|----------|------------|
| DLP Scanner | UPLOAD-001: DLP multipart scanner validates extension but not magic bytes | Medium | 80 |
| DLP Scanner | UPLOAD-002: DLP MaxFileSize check occurs after partial read | Low | 65 |

---

## Finding: UPLOAD-001

**Title:** DLP multipart file scanner validates extensions but not magic bytes
**Severity:** Medium
**Confidence:** 80
**File:** `internal/layers/dlp/layer.go:462-518`
**Vulnerability Type:** CWE-434 (Unrestricted Upload of File with Dangerous Type)
**Description:** The DLP layer's `ScanFileUploads` function validates uploaded files by extension only (e.g., `.php`, `.exe`, `.zip`). It does not validate magic bytes/file signatures. An attacker could upload a malicious file with a spoofed extension (e.g., `malware.php.jpg` detected via double-extension check, or a polyglot file) or bypass extension checks using alternate data streams on Windows (`file.php::$DATA`).
**Impact:** While the DLP scanner blocks known dangerous extensions including double extensions, files with non-standard or homoglyph-attack extensions could bypass detection. More critically, a file that passes DLP scanning could be stored by the upstream application if the WAF is not configured to block uploads.
**Remediation:**
- Implement magic byte validation using a file signature library
- Block uploads based on actual content type, not just extension
- Add support for alternate data stream checks on Windows
- Consider implementing a "first bytes" validation before extension checks

---

## Finding: UPLOAD-002

**Title:** DLP MaxFileSize check occurs after reading file content
**Severity:** Low
**Confidence:** 65
**File:** `internal/layers/dlp/layer.go:426-439`
**Vulnerability Type:** CWE-400 (Uncontrolled Resource Consumption)
**Description:** In `ScanFileUploads`, the file content is read first using `io.ReadAll(io.LimitReader(part, cfg.MaxFileSize+1))` before checking if the size exceeds the limit. The size check `if int64(len(partData)) > cfg.MaxFileSize` happens after the read completes. While `io.LimitReader` provides a hard limit of `MaxFileSize+1`, this pattern could lead to memory exhaustion if `MaxFileSize` is misconfigured or the LimitReader limit is bypassed through boundary issues.
**Impact:** A maliciously large file upload could cause excessive memory usage before being rejected. Limited impact due to the `LimitReader` guard.
**Remediation:**
- Check file size from `Content-Length` header before reading
- Reject oversized uploads earlier in the parsing process
- Add a size check before `io.ReadAll` using `multipart.Reader` limitations

---

## Analysis: No Direct File Upload Endpoints

### Dashboard API Handlers

The GuardianWAF dashboard does **not** expose direct file upload endpoints. All handlers use JSON-based data transfer:

| Handler | Upload Type | Validation |
|---------|-------------|------------|
| `apivalidation_handlers.go` | JSON `content` field | Schema validation only, no file handling |
| `dlp_handlers.go` | JSON pattern definition | No binary upload |
| `virtualpatch_handlers.go` | JSON patch definition | No binary upload |
| `ai_handlers.go` | JSON config (API key, URL) | No file upload |
| `crs_handlers.go` | JSON rule toggle | No file upload |

### TLS Certificate Handling

Certificates are loaded from **disk files only** (`internal/tls/certstore.go:51-60`):
```go
cert, err := tls.LoadX509KeyPair(certFile, keyFile)
```
No HTTP-based certificate upload exists.

### MCP Schema Upload

The MCP `guardianwaf_upload_api_schema` tool accepts schema content as a JSON string field, not binary file upload.

---

## DLP Scanner Security Controls (Good Practices)

The DLP layer implements several protective measures that are working correctly:

1. **MaxFileSize limit** (default 10MB) - `layer.go:51`
2. **Executable file blocking** - Extension list includes `.exe`, `.dll`, `.bat`, `.sh`, etc.
3. **Archive file detection** - `.zip`, `.tar`, `.gz`, `.rar`, `.7z` blocked
4. **Dangerous web extension blocking** - `.php`, `.jsp`, `.asp`, `.cgi`, etc.
5. **Double extension detection** - `isDangerousWebFile()` strips last extension and rechecks
6. **Size-based rejection** - Files exceeding MaxFileSize are flagged

---

## Recommendations

1. **Magic byte validation** - Add file signature checks to complement extension validation
2. **Content-Disposition filename sanitization** - The current code uses `part.FileName()` directly; ensure proper sanitization for path traversal attempts (`../`)
3. **Memory usage limits** - Add pre-check for Content-Length header before multipart parsing
4. **Consider adding a quarantine directory** - For suspicious uploads that pass extension checks but fail deeper inspection

---

## References

- CWE-434: Unrestricted Upload of File with Dangerous Type - https://cwe.mitre.org/data/definitions/434.html
- CWE-400: Uncontrolled Resource Consumption - https://cwe.mitre.org/data/definitions/400.html
