# Race Condition Security Scan Results

**Scanner:** sc-race-condition
**Target:** GuardianWAF - internal/ engine, layers, cluster, tenant, analytics
**Severity Classification:** Critical | High | Medium | Low

---

## Finding: RACE-001

- **Title:** Non-atomic counter increment in IP ACL auto-ban entry
- **Severity:** High
- **Confidence:** 85
- **File:** `internal/layers/ipacl/ipacl.go:30` and `internal/layers/ipacl/ipacl.go:172`
- **Vulnerability Type:** CWE-362 (Race Condition)
- **Description:** The `autoBanEntry.Count` field is declared as a plain `int` (line 30) and incremented without mutex protection in `AddAutoBan()` at line 172. The comment states it is "protected by Layer.mu" but a plain `int` increment (`entry.Count++`) is not atomic and will suffer from lost updates under concurrent requests. Multiple goroutines can increment the same counter simultaneously, causing incorrect violation counts and potentially delaying or bypassing auto-ban triggers.
- **Impact:** An attacker can exploit the race to delay or avoid auto-bans by generating concurrent requests that race on the counter increment. If `rule.AutoBanAfter = 5`, concurrent requests could increment the counter from 0 to only 2 or 3 instead of 5 due to lost updates.
- **Remediation:** Change `Count int` to `Count atomic.Int64` and use `counter.Add(1)` and `counter.Load()` for all accesses. Alternatively, protect all accesses with `Layer.mu`.
- **References:** https://cwe.mitre.org/data/definitions/362.html

---

## Finding: RACE-002

- **Title:** TOCTOU in GeoIP database file loading
- **Severity:** Medium
- **Confidence:** 80
- **File:** `internal/geoip/geoip.go:236-240`
- **Vulnerability Type:** CWE-367 (TOCTOU)
- **Description:** `LoadOrDownload()` checks file existence and freshness via `os.Stat(path)` at line 236, then opens and parses the file via `LoadCSV(path)` at line 238. Between the check and the use, a privileged attacker with file system access could replace the GeoIP CSV with a malicious file (e.g., a symlink to `/etc/passwd` or a crafted file with extreme IP ranges to bypass geo-blocking).
- **Impact:** File system privilege escalation or WAF bypass via crafted GeoIP data. This requires an attacker to already have write access to the geoip.csv path.
- **Remediation:** Open the file directly without a prior stat check, and handle the error from `LoadCSV`. Or use `os.Open` and pass the opened file handle directly to the CSV parser, which resolves the symlink at open time.
- **References:** https://cwe.mitre.org/data/definitions/367.html

---

## Finding: RACE-003

- **Title:** TOCTOU in TLS certificate hot-reload
- **Severity:** Medium
- **Confidence:** 75
- **File:** `internal/tls/certstore.go:217-231`
- **Vulnerability Type:** CWE-367 (TOCTOU)
- **Description:** `reloadIfChanged()` calls `os.Stat(entry.CertFile)` and `os.Stat(entry.KeyFile)` at lines 217-221 to check if files have changed, then conditionally calls `tls.LoadX509KeyPair()` at line 231 to reload. Between the stat and the load, the certificate or key file could be swapped (e.g., atomically replaced via rename). If a malicious actor replaces the key file mid-check, the old (still-valid) cert could be loaded, or conversely a crafted cert could be loaded.
- **Impact:** In shared hosting or compromised environments, an attacker could cause the WAF to load a different certificate than intended, potentially enabling MITM or serving incorrect TLS credentials.
- **Remediation:** Load the new cert directly and replace the old one atomically on success. Use `tls.LoadX509KeyPair` directly rather than stat-then-load, or use a file descriptor that was opened with `O_NOFOLLOW` to prevent symlink attacks.
- **References:** https://cwe.mitre.org/data/definitions/367.html

---

## Finding: RACE-004

- **Title:** sync.Pool context field reset completeness risk
- **Severity:** Low
- **Confidence:** 70
- **File:** `internal/engine/context.go:246-293`
- **Vulnerability Type:** CWE-362 (Race Condition)
- **Description:** `ReleaseContext()` clears all fields on `RequestContext` before returning it to the `sync.Pool`. However, if a future code change adds a new field to `RequestContext` without adding a corresponding reset in `ReleaseContext()`, that field's value could leak between requests (cross-request state leakage). The current implementation does correctly clear all 20+ fields including JA4 fingerprint fields, maps, slices, and pointers.
- **Impact:** Potential cross-request data leakage if the struct is extended without updating `ReleaseContext`. Malicious or accidental data from one request could influence another.
- **Remediation:** Document the invariant that every new field added to `RequestContext` MUST be added to `ReleaseContext()` with an appropriate zero-value reset. Consider adding a test that validates all fields are reset.
- **References:** https://cwe.mitre.org/data/definitions/362.html

---

## Finding: RACE-005

- **Title:** Token bucket map access pattern in rate limiter
- **Severity:** Low
- **Confidence:** 80
- **File:** `internal/layers/ratelimit/ratelimit.go:211-238`
- **Vulnerability Type:** CWE-362 (Race Condition)
- **Description:** `getOrCreateBucket()` performs a check-then-act pattern: it calls `l.buckets.Load(key)` (line 212) to check for existence, then checks `l.bucketCount.Load()` against `maxBuckets` (line 217), and finally calls `l.buckets.LoadOrStore(key, bucket)` (line 233). Under extreme concurrency, two goroutines could simultaneously pass the `Load()` check, both see `bucketCount < maxBuckets`, and both attempt `LoadOrStore`. The second goroutine's bucket would be discarded (LoadOrStore returns the existing bucket), but `bucketCount.Add(1)` was already called by the first goroutine for the newly created bucket, resulting in an inaccurate count.
- **Impact:** The `bucketCount` atomic counter may drift slightly from the actual number of unique buckets under very high concurrency. This is a minor accounting inaccuracy with no direct security impact since `maxBuckets = 500000` provides a large safety margin.
- **Remediation:** This is acceptable for a soft limit. If strict enforcement is required, use a mutex-protected counter that is incremented atomically with the bucket creation.
- **References:** https://cwe.mitre.org/data/definitions/362.html

---

## Finding: RACE-006

- **Title:** Event log rotation uses non-atomic rename-then-reopen pattern
- **Severity:** Low
- **Confidence:** 75
- **File:** `internal/events/file.go:226-253`
- **Vulnerability Type:** CWE-367 (TOCTOU)
- **Description:** `rotateFile()` calls `os.Rename(fs.filePath, rotatedName)` to atomically move the current file, then reopens `fs.filePath` with `os.OpenFile(..., O_CREATE|...)`. On POSIX systems, `rename` is atomic, but on Windows the atomicity guarantees are weaker. Additionally, there is a window between the rename and the reopen where a concurrent reader could fail to open the file.
- **Impact:** Potential temporary event loss or file open errors during rotation under Windows, or in environments where the file store is on network file systems (NFS, CIFS) with weaker atomicity guarantees.
- **Remediation:** On Windows or network file systems, consider opening a new file with a temporary name, writing the header, then atomically renaming over the old file. Ensure readers handle `os.ErrNotExist` gracefully.
- **References:** https://cwe.mitre.org/data/definitions/367.html

---

## Summary

| Finding | Severity | Type | Component |
|---------|----------|------|-----------|
| RACE-001 | **High** | Non-atomic counter | `internal/layers/ipacl/ipacl.go` |
| RACE-002 | Medium | TOCTOU file load | `internal/geoip/geoip.go` |
| RACE-003 | Medium | TOCTOU cert reload | `internal/tls/certstore.go` |
| RACE-004 | Low | Pool reset completeness | `internal/engine/context.go` |
| RACE-005 | Low | Bucket count drift | `internal/layers/ratelimit/ratelimit.go` |
| RACE-006 | Low | Log rotation atomicity | `internal/events/file.go` |

**Most Critical:** RACE-001 in the IP ACL auto-ban counter. Fixing this should be prioritized as it directly affects the WAF's ability to auto-ban malicious IPs under concurrent load.

---

*Scan completed by sc-race-condition skill.*
