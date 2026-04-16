# Hardcoded Secrets Scan Results

**Scanner:** sc-secrets (Hardcoded Secrets Detector)
**Date:** 2026-04-16
**Project:** GuardianWAF
**Files Scanned:** Go source files, YAML configuration files

---

## Summary

| Category | Count |
|----------|-------|
| Critical Issues | 0 |
| High Issues | 0 |
| Medium Issues | 0 |
| Low Issues (Info/False Positives) | 0 |

**Result:** NO HARDCODED SECRETS DETECTED

---

## Detailed Findings

### Secrets Management Assessment

#### 1. Dashboard Authentication
- **Location:** `internal/dashboard/auth.go`
- **Status:** SECURE
- **Details:** Session secrets are generated using `crypto/rand` at initialization. The `SetSessionSecret()` function allows persistent secrets from config, but defaults to cryptographically secure random generation.

#### 2. Dashboard Password Generation
- **Location:** `cmd/guardianwaf/main.go:698` and `cmd/guardianwaf/main_default.go:689`
- **Status:** SECURE
- **Details:** `generateDashboardPassword()` uses `cryptoRand.Read(b)` for cryptographically secure random password generation. Fallback uses SHA256 hash of process state + entropy sources.

#### 3. Configuration Secrets Loading
- **Location:** `internal/config/defaults.go`, `internal/config/config.go`
- **Status:** SECURE
- **Details:** Default values for all secrets (API keys, passwords, shared secrets) are empty strings. Secrets are loaded from:
  - YAML configuration files
  - Environment variables (GWAF_* prefix)
  - CLI flags

#### 4. TLS/Private Keys
- **Status:** SECURE
- **Details:** TLS certificate paths (`cert_file`, `key_file`) are file paths loaded from config, not embedded certificates. No private keys found hardcoded in source.

#### 5. SIEM/API Security/JWT Configuration
- **Location:** `internal/config/config.go:1114-1126`
- **Status:** SECURE
- **Details:** All credentials (SIEM API key, JWT public keys, etc.) are loaded from YAML/config. No defaults are hardcoded.

---

## Example/Non-Production Values (Not Security Issues)

The following are intentional example values in test data and example configurations:

| File | Value | Context |
|------|-------|---------|
| `examples/standalone/guardianwaf.yaml:202` | `api_key: "guardianwaf-demo-2024"` | Example config with comment "Change this! Set a strong key" |
| `testdata/realtest.yaml:127` | `api_key: "test-api-key-2024"` | Test data for integration tests |
| `testdata/configs/full.yml:159` | `api_key: "test-api-key-12345"` | Full config test data |

These are not production secrets as they are clearly marked as demo/test values.

---

## Test File Patterns (False Positives)

The following patterns appear in test files but are NOT hardcoded secrets:

| File | Pattern | Context |
|------|---------|---------|
| `internal/layers/response/response_test.go:801` | `password = "abcdefghijklmnopqrstuvwxyz"` | Test for password masking |
| `internal/layers/response/response_test.go:817` | `auth_token: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ123456'` | Test for token masking |
| `internal/layers/dlp/layer_test.go:224` | `api_key: sk_live_abcdef1234567890` | Test payload for DLP detector |
| `cmd/guardianwaf/main_cli_test.go:664` | `api_key: testsecret` | Test configuration |
| `cmd/guardianwaf/main_test.go:899` | `cfg.Dashboard.APIKey = "test-api-key"` | Unit test setup |

---

## Security Best Practices Observed

1. **Zero hardcoded credentials** - No API keys, passwords, or secrets embedded in source code
2. **Crypto-random secrets** - Dashboard and session secrets use `crypto/rand`
3. **Environment variable support** - Secrets can be injected via `GWAF_*` environment variables
4. **Configuration layering** - Secrets follow priority: defaults → YAML → env vars → CLI flags
5. **Placeholder comments** - Example configs use clear placeholder text (e.g., "CHANGE-THIS-IN-PRODUCTION")

---

## Recommendations

1. **No action required** - No hardcoded secrets were found in production code paths.
2. **Example configs** - The `examples/standalone/guardianwaf.yaml` contains a demo API key. Ensure users of this example change it before production use (the file already contains a comment to this effect).
3. **Consider adding** `.env.example` file with all environment variable names documented for easier secret management.

---

## References

- CWE-798: Use of Hardcoded Credentials
- CWE-321: Use of Hard-coded Cryptographic Key
