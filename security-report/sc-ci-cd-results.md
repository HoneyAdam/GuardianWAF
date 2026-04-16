# CI/CD Pipeline Security Report

**Scanner:** sc-ci-cd
**Date:** 2026-04-16
**Files Scanned:** `.github/workflows/ci.yml`, `.github/workflows/release.yml`, `.github/workflows/website.yml`

---

## Summary

| Severity | Count |
|----------|-------|
| Critical | 0 |
| High | 3 |
| Medium | 8 |
| Low | 0 |

---

## Findings

### CICD-001: Third-Party GitHub Actions Not Pinned to Commit SHA

- **Severity:** Medium
- **Confidence:** 100
- **File:** `.github/workflows/ci.yml:13,15,74,91,97,104,109,114`
- **CWE:** CWE-829
- **Description:** Multiple third-party actions reference mutable version tags (e.g., `@v4`, `@v5`, `@v7`) instead of immutable commit SHAs. Tags can be moved to malicious commits without warning.
- **Affected Actions:**
  - `actions/checkout@v4` (lines 13, 52, 84, 105, 64)
  - `actions/setup-node@v4` (lines 15, 23)
  - `codecov/codecov-action@v5` (line 74)
  - `golangci/golangci-lint-action@v7` (line 97)
  - `actions/upload-artifact@v4` (lines 38, 59)
  - `actions/download-artifact@v4` (lines 59, 91, 114)
- **Impact:** Supply chain compromise if a tag is moved to a malicious commit.
- **Remediation:** Replace all mutable tags with full commit SHAs. Example: `actions/checkout@v4` -> `actions/checkout@b4ff28c23612911e5e8a67d50e3c52e31e6ef8f8`.
- **Reference:** https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions

---

### CICD-002: Third-Party GitHub Actions Not Pinned to Commit SHA (release.yml)

- **Severity:** Medium
- **Confidence:** 100
- **File:** `.github/workflows/release.yml:15,19,23,40,49,56,81,90,97,100`
- **CWE:** CWE-829
- **Description:** Multiple third-party actions in the release workflow use mutable version tags instead of immutable commit SHAs.
- **Affected Actions:**
  - `actions/checkout@v4`
  - `actions/setup-go@v5`
  - `actions/setup-node@v4`
  - `goreleaser/goreleaser-action@v6`
  - `anchore/sbom-action@v0`
  - `softprops/action-gh-release@v2`
  - `docker/metadata-action@v5`
  - `docker/login-action@v3`
  - `docker/setup-buildx-action@v3`
  - `docker/build-push-action@v6`
- **Impact:** Supply chain compromise — a malicious actor could modify a tag to point to compromised code, executing arbitrary code during release builds with write permissions to GitHub Packages.
- **Remediation:** Pin all third-party actions to full commit SHAs. Prioritize `goreleaser/goreleaser-action@v6` and `docker/login-action@v3` as they operate with write access.
- **Reference:** https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions

---

### CICD-003: Third-Party GitHub Actions Not Pinned to Commit SHA (website.yml)

- **Severity:** Medium
- **Confidence:** 100
- **File:** `.github/workflows/website.yml:25,28,39,46,59`
- **CWE:** CWE-829
- **Description:** Multiple third-party actions use mutable version tags instead of immutable commit SHAs.
- **Affected Actions:**
  - `actions/checkout@v4`
  - `actions/setup-node@v4`
  - `actions/configure-pages@v4`
  - `actions/upload-pages-artifact@v3`
  - `actions/deploy-pages@v4`
- **Impact:** Supply chain compromise via tag mutation.
- **Remediation:** Pin all third-party actions to full commit SHAs.
- **Reference:** https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions

---

### CICD-004: Missing Static Application Security Testing (SAST)

- **Severity:** High
- **Confidence:** 100
- **File:** `.github/workflows/ci.yml`
- **CWE:** CWE-1104
- **Description:** The CI pipeline does not include SAST scanning (e.g., CodeQL, Semgrep, or Gosec) for Go code or ESLint/Semgrep for JavaScript/TypeScript dashboard code.
- **Impact:** Security vulnerabilities, injection flaws, and insecure coding patterns may be merged without detection.
- **Remediation:** Add `github/codeql-action/init` with `languages: [go, javascript]` or use `golangci/golangci-lint-action` with security-related linters enabled. Add `npm run lint` already exists for the dashboard, but consider adding `npm audit --audit-level=critical` and SAST for the Go backend.
- **Reference:** https://docs.github.com/en/code-security/code-scanning/integrating-with-gitub-code-scanning

---

### CICD-005: Missing Container Image Vulnerability Scanning

- **Severity:** High
- **Confidence:** 100
- **File:** `.github/workflows/release.yml:99`
- **CWE:** CWE-1104
- **Description:** The Docker build step (line 99) builds and pushes multi-architecture images (`linux/amd64,linux/arm64`) but does not scan the resulting images for vulnerabilities before or after push. Only an SBOM is generated, but no vulnerability scanning (e.g., Trivy, Snyk Container) is performed.
- **Impact:** Vulnerable container images may be published to GHCR and used in production environments.
- **Remediation:** Add a Trivy scan step after the Docker build: `uses: aquasecurity/trivy-action@master` with `scan-type: 'image'` and `severity: 'CRITICAL,HIGH'`. Block the pipeline if critical vulnerabilities are found.
- **Reference:** https://aquasecurity.github.io/trivy/

---

### CICD-006: Missing Secret Scanning in CI Pipeline

- **Severity:** High
- **Confidence:** 100
- **File:** `.github/workflows/ci.yml`
- **CWE:** CWE-798
- **Description:** The CI pipeline does not run secret scanning tools (e.g., TruffleHog, gitleaks, or GitHub Advanced Security's secret scanning) to detect committed secrets in the codebase.
- **Impact:** Accidentally committed credentials, API keys, or tokens may go undetected and be deployed to production.
- **Remediation:** Add `步: uses: trufflesecurity/truffleHog-action@main` or enable GitHub Advanced Security secret scanning on the repository settings.
- **Reference:** https://docs.github.com/en/enterprise-cloud@latest/code-security/secret-scanning

---

### CICD-007: Release Workflow Uses Broad write Permissions

- **Severity:** Medium
- **Confidence:** 90
- **File:** `.github/workflows/release.yml:7-9`
- **CWE:** CWE-269
- **Description:** The release workflow requests `permissions: contents: write, packages: write` globally. These broad permissions allow the workflow to write to all repositories and packages, increasing the blast radius if the workflow is compromised.
- **Impact:** If an attacker injects code into a third-party action used in the release workflow, they gain write access to GitHub releases and packages.
- **Remediation:** Move permissions to the specific job that needs them (goreleaser and docker jobs) rather than the workflow level. Use the principle of least privilege for each job.
- **Reference:** https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#permissions

---

### CICD-008: No Dependency Vulnerability Scanning for Go Modules

- **Severity:** Medium
- **Confidence:** 100
- **File:** `.github/workflows/ci.yml`
- **CWE:** CWE-1104
- **Description:** The CI pipeline runs `go test` and `go vet` but does not scan Go dependencies for known vulnerabilities (e.g., `govulncheck`, `nancy`, or `Socket's Go dependency scanning`).
- **Impact:** Known vulnerable dependencies may be used without detection, leading to exploitable vulnerabilities in production.
- **Remediation:** Add `uses: golang/govulncheck-action@v1` or integrate with a dependency scanning tool like Snyk or Dependabot alerts.
- **Reference:** https://go.dev/security/vuln/

---

### CICD-009: Build Args Include Potentially Untrusted GitHub Context Data

- **Severity:** Medium
- **Confidence:** 70
- **File:** `.github/workflows/release.yml:107-111`
- **CWE:** CWE-94
- **Description:** Docker build args use `${{ github.sha }}`, `${{ github.ref_name }}`, and `${{ github.event.head_commit.timestamp }}`. While these derive from the tag push event (not directly from user input), `github.event.head_commit.timestamp` comes from commit data which could theoretically be manipulated.
- **Impact:** If a commit author manipulates the commit timestamp, it could affect the build metadata. In practice, this is low risk since the workflow only triggers on tag pushes from protected branches.
- **Remediation:** Prefer values that are guaranteed to be controlled by the workflow trigger (e.g., `github.ref_name` from the tag is safe). For the timestamp, use `${{ github.event.created_at }}` or a fixed date format from a trusted source.
- **Reference:** https://docs.github.com/en/actions/learn-github-actions/contexts#github-context

---

### CICD-010: Missing Pipeline Concurrency Controls on CI Workflow

- **Severity:** Medium
- **Confidence:** 80
- **File:** `.github/workflows/ci.yml`
- **CWE:** CWE-362
- **Description:** The CI workflow does not define a `concurrency` block, allowing parallel runs on the same ref to interfere with each other. This is especially problematic for coverage uploads and benchmark comparisons.
- **Impact:** Race conditions between concurrent CI runs could cause coverage data corruption or misleading benchmark comparisons.
- **Remediation:** Add a concurrency group to cancel in-progress runs on the same branch/PR:
  ```yaml
  concurrency:
    group: ${{ github.workflow }}-${{ github.ref }}
    cancel-in-progress: true
  ```
- **Reference:** https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#concurrency

---

## Positive Security Observations

- No secrets are hardcoded in any workflow file.
- No `pull_request_target` trigger is used, avoiding the most dangerous GitHub Actions vulnerability pattern.
- The `website.yml` workflow correctly uses minimal permissions (`contents: read`).
- The `ci.yml` workflow correctly uses minimal permissions for most jobs.
- SBOM generation is included in the release workflow (`anchore/sbom-action@v0`).
- `npm audit` is run on the dashboard dependencies.
- Branch protection is implicitly required since pushes only target `main`.

---

## Recommendations (Priority Order)

1. **Pin all third-party actions to commit SHAs** — This is the single highest-impact fix to prevent supply chain attacks.
2. **Enable CodeQL SAST scanning** in the CI pipeline for Go and JavaScript.
3. **Add Trivy container image scanning** in the release workflow before pushing.
4. **Add secret scanning** (TruffleHog or GitHub Advanced Security).
5. **Add Go dependency vulnerability scanning** (`govulncheck`).
6. **Add concurrency controls** to the CI workflow to cancel redundant runs.
7. **Restrict release workflow permissions** to job-level rather than workflow-level.

---

## Files Scanned

| File | Workflow Type |
|------|---------------|
| `.github/workflows/ci.yml` | Continuous Integration |
| `.github/workflows/release.yml` | Release & Container Build |
| `.github/workflows/website.yml` | GitHub Pages Deployment |

No other CI/CD configurations found (no `.gitlab-ci.yml`, `Jenkinsfile`, `.circleci/config.yml`, or `azure-pipelines.yml`).
