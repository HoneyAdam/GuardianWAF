# Path Traversal Security Scan Results

**Scanner:** sc-path-traversal
**Target:** GuardianWAF
**Date:** 2026-04-16

---

## Summary

| Severity | Count |
|----------|-------|
| Critical | 0 |
| High | 0 |
| Medium | 1 |
| Low | 1 |

---

## Finding: PATH-001

- **Title:** Weak Path Traversal Protection in Dashboard Static Asset Serving
- **Severity:** Medium
- **Confidence:** 75
- **File:** `internal/dashboard/dashboard.go:1835-1843`
- **Vulnerability Type:** CWE-22 (Path Traversal)
- **Description:** The `handleDistAssets` function uses a simple `strings.Contains(cleanPath, "..")` check to prevent path traversal when serving static assets from the embedded `distFS` filesystem. While Go's `http` package URL-decodes `r.URL.Path` before the handler receives it, relying on literal string matching for `..` is fragile. A more robust approach would use `filepath.Clean` and verify the resolved path stays within the intended directory.
- **Impact:** Limited file read from embed.FS (go:embed), no arbitrary system file access since embed.FS is bounded to compiled binaries.
- **Remediation:** Replace the `strings.Contains` check with canonicalization:
  ```go
  absPath, err := filepath.Abs(filePath)
  if err != nil { http.NotFound(w,r); return }
  absBase, err := filepath.Abs("dist")
  if err != nil { http.NotFound(w,r); return }
  if !strings.HasPrefix(absPath, absBase+string(filepath.Separator)) {
      http.NotFound(w, r)
      return
  }
  ```
- **References:** https://cwe.mitre.org/data/definitions/22.html

---

## Finding: PATH-002

- **Title:** Lack of Path Validation for TLS Certificate File Paths via Dashboard API
- **Severity:** Low
- **Confidence:** 60
- **File:** `internal/dashboard/dashboard.go:805-811`
- **Vulnerability Type:** CWE-22 (Path Traversal)
- **Description:** The `handleUpdateRouting` function accepts `cert_file` and `key_file` paths in the virtual host TLS configuration from the JSON request body without validating that the paths are within an expected directory or are safe file paths. While this requires API key authentication, an authenticated attacker with write access to the dashboard API could specify paths like `../../etc/ssl/private/key.pem` to write to arbitrary locations (if combined with other vulnerabilities) or confirm existence of files outside the intended scope.
- **Impact:** Requires authenticated API access; can only confirm existence/read files accessible to the process, cannot write arbitrary files through this vector alone.
- **Remediation:** Validate that cert/key file paths are absolute or resolve to within an allowed directory:
  ```go
  absCert, _ := filepath.Abs(vh.TLS.CertFile)
  if !isWithinAllowedDir(absCert, allowedCertDirs) {
      writeJSON(w, http.StatusBadRequest, map[string]any{"error": "cert_file path not allowed"})
      return
  }
  ```
- **References:** https://cwe.mitre.org/data/definitions/22.html

---

## Findings: Secure Implementations (Not Vulnerable)

The following areas were reviewed and found to have proper path traversal protections:

### 1. Replay Layer - `ReplayRecording` Function
**File:** `internal/layers/replay/replayer.go:168-184`

Uses `filepath.Abs` for canonicalization and validates the resolved path stays within the storage directory:
```go
abs, err := filepath.Abs(filePath)
// ...
if !strings.HasPrefix(abs, absBase+string(filepath.Separator)) && abs != absBase {
    return nil, fmt.Errorf("recording %q escapes storage directory", filename)
}
```
**Verdict:** Secure.

### 2. Dashboard API - Virtual Host Domain Configuration
**File:** `internal/dashboard/dashboard.go:797-803`

Domain validation uses string assignment only, no path construction from user input:
```go
if domains, ok := raw["domains"].([]any); ok {
    for _, d := range domains {
        if s, ok := d.(string); ok {
            vh.Domains = append(vh.Domains, s)
        }
    }
}
```
**Verdict:** Not vulnerable.

### 3. Config File Loading - `LoadFile` / `LoadDir`
**File:** `internal/config/validate.go:50-110`

The `LoadDir` function constructs paths using `dir + string(os.PathSeparator) + filename`. The `dir` parameter comes from CLI flags or config, not from user requests. The function uses `os.ReadDir` which does not follow symlinks and properly enumerates directory contents.
**Verdict:** Not vulnerable (admin-controlled paths only).

### 4. TLS Certificate Loading
**File:** `internal/tls/certstore.go:51-60, 63-103`

The `LoadDefaultCert` and `LoadCert` functions take `certFile` and `keyFile` as parameters which are loaded from the guardianwaf configuration file (YAML), not from HTTP requests. This is an admin-controlled path.
**Verdict:** Not vulnerable (admin-controlled paths only).

### 5. GeoIP Database Loading
**File:** `internal/geoip/geoip.go:50-115`

`LoadCSV` accepts a `path` parameter from configuration, not from user input. The `StartAutoRefresh` function uses `os.Create(path)` where `path` comes from config.
**Verdict:** Not vulnerable (admin-controlled paths only).

### 6. Threat Intel Feed Loading
**File:** `internal/layers/threatintel/feed.go:161-169`

The `loadFile` function opens a feed file at `f.config.Path`, which is loaded from configuration. SSRF protection is applied to URL-based feeds (line 173-177), but file-based feeds are admin-controlled.
**Verdict:** Not vulnerable (admin-controlled paths only).

### 7. Event File Storage
**File:** `internal/events/file.go:39-60`

The `NewFileStore` function creates a file at a path passed during construction, which comes from the `events.file_path` configuration field. File rotation uses timestamp-based naming and stays within the original directory.
**Verdict:** Not vulnerable (admin-controlled paths only).

### 8. Analytics Storage
**File:** `internal/analytics/collector.go:507-536`

The `Flush` function writes metrics to `filepath.Join(c.config.StoragePath, fmt.Sprintf("metrics-%s.json", time.Now().Format("20060102")))`. The `StoragePath` is from configuration, and the filename is generated from the current date.
**Verdict:** Not vulnerable (admin-controlled paths only).

### 9. Billing Storage
**File:** `internal/tenant/billing.go:321-339, 343-368`

Uses `bm.storePath` from configuration with atomic rename (`os.Rename(tmpFile, bm.storePath)`) and directory creation via `os.MkdirAll`.
**Verdict:** Not vulnerable (admin-controlled paths only).

### 10. Log Buffer
**File:** `internal/engine/logbuffer.go`

The `LogBuffer` is a pure in-memory ring buffer with no file I/O. No path traversal risk.
**Verdict:** Not applicable.

---

## Conclusion

GuardianWAF's codebase demonstrates good awareness of path traversal risks. The primary attack surface is limited to authenticated dashboard API users, and most file operations use admin-controlled configuration paths rather than direct user input. The one area requiring attention (PATH-001) has defense-in-depth due to the use of Go's `embed.FS` which cannot be escaped to access arbitrary system files even if path traversal were successful.
