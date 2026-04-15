# Path Traversal Security Scan Results

**Scanner:** sc-path-traversal
**Target:** GuardianWAF (Pure Go WAF codebase)
**Date:** 2026-04-15

## Summary

**No path traversal vulnerabilities found.**

The codebase implements multiple layers of protection against path traversal attacks:

- Static assets served via `embed.FS` (compiled into binary)
- Path normalization with `path.Clean()` in proxy router
- Explicit path confinement checks in sensitive operations
- Configuration-based file paths (not user-controlled)

---

## Analysis by Component

### 1. Dashboard Static File Serving

**Status:** Secure

The dashboard uses `embed.FS` to serve static assets. Files are compiled into the binary at build time, making filesystem traversal impossible.

```go
// internal/dashboard/dashboard.go:27-33
var distFS embed.FS  // React build output (Vite-hashed assets)
var staticFiles embed.FS  // Legacy static files
```

The `handleDistAssets` function (dashboard.go:1743) performs `..` validation:
```go
cleanPath := strings.TrimPrefix(r.URL.Path, "/assets/")
if strings.Contains(cleanPath, "..") {
    http.NotFound(w, r)
    return
}
```

Since `embed.FS` is used (not os filesystem), traversal cannot escape the embedded filesystem.

### 2. Proxy Router Path Handling

**Status:** Secure

The proxy router uses `path.Clean()` to normalize paths before route matching:

```go
// internal/proxy/router.go:85
reqPath := path.Clean(r.URL.Path)
```

This prevents bypasses via `//`, `/../`, and similar techniques.

### 3. API Validation Layer

**Status:** Secure

The `readFile` function in the API validation layer implements explicit path confinement:

```go
// internal/layers/apivalidation/layer.go:212-232
func (l *Layer) readFile(path string) ([]byte, error) {
    absPath, err := filepath.Abs(path)
    // ...
    cwd, err := os.Getwd()
    // Ensure the resolved path is within the working directory
    if !strings.HasPrefix(absPath, cwd+string(filepath.Separator)) && absPath != cwd {
        return nil, fmt.Errorf("path outside allowed directory")
    }
    return os.ReadFile(absPath)
}
```

### 4. Replay Layer

**Status:** Secure

The `ReplayRecording` function properly validates paths before access:

```go
// internal/layers/replay/replayer.go:168-184
func (r *Replayer) ReplayRecording(ctx context.Context, storagePath, filename string, filter ReplayFilter) (*ReplayStats, error) {
    filePath := filepath.Join(storagePath, filename)
    abs, err := filepath.Abs(filePath)
    absBase, err := filepath.Abs(storagePath)
    if !strings.HasPrefix(abs, absBase+string(filepath.Separator)) && abs != absBase {
        return nil, fmt.Errorf("recording %q escapes storage directory", filename)
    }
    return r.ReplayFile(ctx, filePath, filter)
}
```

### 5. Config/TLS/GeoIP/Event File Operations

**Status:** Secure

All file operations in these components use paths derived from operator configuration, not from HTTP request input:

- **Config loading**: Paths from CLI flags/config files
- **TLS cert loading**: Paths from WAF configuration
- **GeoIP CSV loading**: Paths from WAF configuration
- **Event file store**: Paths from WAF configuration

### 6. Event Export API

**Status:** Secure

The `/api/v1/events/export` endpoint does not serve files from disk. It queries the event store and writes results directly to the HTTP response in JSON/CSV format. Query parameters (`path`, `action`, etc.) are used for filtering, not filesystem access.

---

## Search Patterns Checked

| Pattern | Found | Risk |
|---------|-------|------|
| `filepath.Join` | Yes (test files, config paths) | Low - operator-controlled |
| `path.Join` | Yes (test files) | Low - internal paths |
| `path.Clean` | Yes (router.go:85) | Low - used defensively |
| `ServeFile` | No | N/A |
| `ioutil.ReadFile` | No (uses `os.ReadFile`) | N/A |
| `os.Open` | Yes (config/geoip/replay) | Low - operator-controlled |

---

## Conclusion

No path traversal vulnerabilities were identified. The codebase demonstrates good security practices:

1. Uses `embed.FS` for static assets (immutable, compiled into binary)
2. Validates and normalizes HTTP request paths with `path.Clean()`
3. Implements explicit path confinement checks where filesystem access is required
4. All sensitive file operations use operator-controlled paths, not user input

**Recommendation:** No path traversal remediation required.
