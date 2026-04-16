# SC-Crypto: Cryptography Misuse Scan Results

**Scanner:** sc-crypto v1.0.0  
**Scan Date:** 2026-04-16  
**Status:** COMPLETE

---

## Summary

| Category | Result |
|----------|--------|
| crypto/mrand usage | PASS (none found) |
| TLS MinVersion | PASS (TLS 1.3 enforced) |
| InsecureSkipVerify | PASS (tests only, false-positive) |
| Weak ciphers (RC4/ECB) | PASS (none found) |
| Hardcoded keys | PASS (none found) |
| MD5/SHA1 for security | PASS (protocol-compliant only) |
| crypto/rand usage | PASS (all use crypto/rand) |

---

## Detailed Findings

### CRYPTO-001: SHA1 Used for OCSP Certificate ID (Protocol-Compliant)
- **Severity:** Low
- **Confidence:** 90
- **File:** `internal/tls/ocsp.go:241`
- **Vulnerability Type:** CWE-327 (Broken Crypto)
- **Description:** SHA1 is used to hash issuer Subject and public key for OCSP CertID construction (RFC 6960 requires specific hash algorithms, and SHA1 is used here for OCSP protocol compliance, not for general security).
- **Impact:** No practical impact — OCSP is a protocol where the hash is part of the request structure, not protecting sensitive data.
- **Remediation:** No action needed. OCSP RFC mandates specific hash algorithms for CertID. Using SHA1 here is protocol-compliant and required for OCSP responder compatibility.
- **References:** [RFC 6960 OCSP](https://cwe.mitre.org/data/definitions/327.html), [RFC 6960 Section 4.4.1](https://datatracker.ietf.org/doc/html/rfc6960#section-4.4.1)

---

### CRYPTO-002: SHA1 Used for WebSocket Accept Key (Protocol-Required)
- **Severity:** Low
- **Confidence:** 90
- **File:** `internal/layers/websocket/websocket.go:572`
- **Vulnerability Type:** CWE-327 (Broken Crypto)
- **Description:** SHA1 is used in `GenerateAcceptKey()` per RFC 6455 Section 4.2.2, which explicitly mandates SHA-1 for WebSocket handshake key derivation.
- **Impact:** No impact — WebSocket protocol specification (RFC 6455) requires SHA-1 for the Sec-WebSocket-Accept header. This is a protocol requirement, not a cryptographic weakness.
- **Remediation:** No action needed. This is a protocol mandated algorithm and cannot be changed without breaking WebSocket compatibility.
- **References:** [RFC 6455 Section 4.2.2](https://datatracker.ietf.org/doc/html/rfc6455#section-4.2.2)

---

### CRYPTO-003: MD5 Used for JA3 TLS Fingerprinting (Non-Security)
- **Severity:** Low
- **Confidence:** 85
- **File:** `internal/layers/botdetect/ja3.go:33`
- **Vulnerability Type:** CWE-327 (Broken Crypto)
- **Description:** MD5 is used to compute JA3 TLS fingerprint hashes. JA3 is a fingerprinting mechanism, not a security primitive — it generates a short identifier from TLS ClientHello parameters for bot detection.
- **Impact:** No impact — JA3 is used for TLS fingerprinting/bot detection, not for authentication, signatures, or protecting sensitive data. MD5's collision vulnerabilities are irrelevant for fingerprinting.
- **Remediation:** No action needed. MD5 is acceptable for non-security fingerprinting use cases. Replacing with SHA-256 would break JA3 compatibility with existing bot detection feeds (Spur, ThreatFox, etc.).
- **References:** [JA3 Fingerprinting](https://github.com/salesforce/ja3)

---

### CRYPTO-004: Weak TLS CBC Ciphers in Cipher Name Map
- **Severity:** Medium
- **Confidence:** 75
- **File:** `internal/engine/event.go:214-215`
- **Vulnerability Type:** CWE-327 (Broken Crypto)
- **Description:** `TLS_RSA_WITH_AES_128_CBC_SHA` (0x002f) and `TLS_RSA_WITH_AES_256_CBC_SHA` (0x0035) are listed in the cipher name map. These are CBC-mode ciphers with MAC-then-encrypt (MT) which has known vulnerabilities (BEAST, POODLE).
- **Impact:** These ciphers are listed only for name resolution in TLS event logging. The actual TLS configuration in `internal/tls/certstore.go:137` enforces `MinVersion: tls.VersionTLS13` (TLS 1.3 only), so these weak ciphers are never actually used in any TLS connection.
- **Remediation:** No action needed for security — the TLS config enforces TLS 1.3 which does not use these ciphers. Consider removing from the map for code hygiene.
- **References:** [CWE-327](https://cwe.mitre.org/data/definitions/327.html)

---

### CRYPTO-005: InsecureSkipVerify in CLI Test
- **Severity:** Low
- **Confidence:** 95
- **File:** `cmd/guardianwaf/main_cli_test.go:981`
- **Vulnerability Type:** CWE-295 (Improper Certificate Validation)
- **Description:** `InsecureSkipVerify: true` is used in a test to verify TLS connectivity to a locally served endpoint.
- **Impact:** Low — this is a test-only code path that connects to a local test server (`127.0.0.1`). It does not affect production traffic.
- **Remediation:** No action needed for production security. Consider using a self-signed cert fixture and proper verification in tests.
- **References:** [CWE-295](https://cwe.mitre.org/data/definitions/295.html)

---

### CRYPTO-006: crypto/rand Usage Verification
- **Severity:** Informational
- **Confidence:** 100
- **Files:** Multiple (auth.go, challenge.go, context.go, cluster.go, canary.go, tenant/manager.go, tenant/alerts.go, ai/store.go, ai/remediation/engine.go, zerotrust/service.go, clustersync/types.go, clustersync/manager.go, acme/client.go)
- **Vulnerability Type:** CWE-330 (Insufficient Randomness)
- **Description:** All security-sensitive random number generation correctly uses `crypto/rand.Read()`. No usage of `crypto/mrand` (insecure RNG) was found.
- **Impact:** None — strong cryptographic RNG is used throughout.
- **Remediation:** No action needed.
- **References:** [CWE-330](https://cwe.mitre.org/data/definitions/330.html)

---

### CRYPTO-007: TLS 1.3 Minimum Version Enforcement
- **Severity:** Informational
- **Confidence:** 100
- **File:** `internal/tls/certstore.go:137`
- **Vulnerability Type:** CWE-327 (Broken Crypto)
- **Description:** TLS configuration enforces `MinVersion: tls.VersionTLS13` — only TLS 1.3 is permitted. TLS 1.2 and below are disabled.
- **Impact:** Strong cipher suites only — TLS 1.3 uses AEAD ciphers (AES-GCM, ChaCha20-Poly1305) with forward secrecy. Weak ciphers and deprecated TLS versions are not configurable.
- **Remediation:** No action needed. This is the recommended configuration.
- **References:** [TLS 1.3 Security](https://cwe.mitre.org/data/definitions/327.html)

---

## Conclusion

**Overall Status:** SECURE

The codebase demonstrates good cryptography hygiene:

1. **No crypto/mrand** — all security RNG uses `crypto/rand`
2. **TLS 1.3 minimum** — strong cipher suites enforced
3. **HMAC-SHA256 for sessions** — strong MAC for session tokens
4. **Constant-time comparison** — `subtle.ConstantTimeCompare` used for API key comparison

The SHA1 and MD5 usages are **all protocol-compliant or non-security-purpose**:
- SHA1 for OCSP (RFC 6960 requirement)
- SHA1 for WebSocket (RFC 6455 requirement)
- MD5 for JA3 fingerprinting (not a security primitive)

No hardcoded keys, no ECB mode, no weak cipher suites in active use, no certificate validation bypasses in production code.
