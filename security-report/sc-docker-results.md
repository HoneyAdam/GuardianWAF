# Docker Security Scan Results

**Scanner:** sc-docker
**Target:** GuardianWAF
**Files Scanned:**
- `D:/CODEBOX/PROJECTS/GuardianWAF/Dockerfile`
- `D:/CODEBOX/PROJECTS/GuardianWAF/examples/sidecar/Dockerfile`
- `D:/CODEBOX/PROJECTS/GuardianWAF/docker-compose.yml`
- `D:/CODEBOX/PROJECTS/GuardianWAF/docker-compose.test.yml`
- `D:/CODEBOX/PROJECTS/GuardianWAF/docker-compose.prod.yml`
- `D:/CODEBOX/PROJECTS/GuardianWAF/examples/sidecar/docker-compose.yml`
- `D:/CODEBOX/PROJECTS/GuardianWAF/internal/docker/client.go`
- `D:/CODEBOX/PROJECTS/GuardianWAF/.dockerignore`

---

## Summary

| Severity | Count |
|----------|-------|
| Critical | 0 |
| High     | 4 |
| Medium   | 5 |
| Low      | 0 |

---

## Findings

### DOCK-001: Container Runs as Root in docker-compose.test.yml
- **Severity:** High
- **Confidence:** 100
- **File:** `docker-compose.test.yml:24` (guardianwaf service), `docker-compose.test.yml:8` (backend service)
- **Vulnerability Type:** CWE-250 (Execution with Unnecessary Privileges)
- **Description:** The `guardianwaf` and `backend` services in `docker-compose.test.yml` run as root by default. No `user` directive is specified, and no `security_opt: no-new-privileges:true` is set.
- **Impact:** If a container is compromised, the attacker has root privileges on the container. Container breakout would give root access to the host.
- **Remediation:** Add `user: "guardianwaf:guardianwaf"` or `user: "1000:1000"` to the service definitions. For the backend service, create a non-root user.
- **References:** https://docs.docker.com/develop/security-best-practices/

### DOCK-002: Missing Security Options in docker-compose.yml (dev)
- **Severity:** High
- **Confidence:** 100
- **File:** `docker-compose.yml:6`
- **Vulnerability Type:** CWE-250 (Execution with Unnecessary Privileges)
- **Description:** The `guardianwaf` service lacks `security_opt`, `cap_drop: ALL`, and `read_only: true` directives. The service runs with default Docker capabilities.
- **Impact:** Container has all default Linux capabilities. A vulnerability could allow privilege escalation.
- **Remediation:** Add the following to the guardianwaf service:
  ```yaml
  security_opt:
    - no-new-privileges:true
  cap_drop:
    - ALL
  read_only: true
  tmpfs:
    - /tmp
  ```
- **References:** SC-DOCK-046, SC-DOCK-047, SC-DOCK-048, SC-DOCK-099, SC-DOCK-100, SC-DOCK-101

### DOCK-003: Using Mutable `latest` Tag for Production Image
- **Severity:** High
- **Confidence:** 100
- **File:** `docker-compose.yml:7`, `examples/sidecar/docker-compose.yml:7`
- **Vulnerability Type:** CWE-829 (Improper Restriction of Repeated Authentication Attempts)
- **Description:** Both compose files reference `ghcr.io/guardianwaf/guardianwaf:latest`. Using mutable tags means the image could change unexpectedly between deployments.
- **Impact:** Deployments are not reproducible. A compromised registry could serve a different image with the same tag.
- **Remediation:** Pin to a specific digest: `ghcr.io/guardianwaf/guardianwaf@sha256:abc123...`
- **References:** SC-DOCK-003, SC-DOCK-015

### DOCK-004: Missing Resource Limits in docker-compose.yml (dev)
- **Severity:** High
- **Confidence:** 100
- **File:** `docker-compose.yml:6`
- **Vulnerability Type:** CWE-770 (Improper Reset of a Resource Exhaustion)
- **Description:** The `guardianwaf`, `backend`, and `backend2` services have no memory or CPU limits defined. `examples/sidecar/docker-compose.yml` correctly defines limits (memory: 128M, cpus: 0.5), but the main dev compose does not.
- **Impact:** A misbehaving or compromised container can consume all host resources (memory, CPU), causing denial of service for other containers and the host system.
- **Remediation:** Add `deploy.resources.limits` to all services:
  ```yaml
  deploy:
    resources:
      limits:
        memory: 256M
        cpus: 1.0
  ```
- **References:** SC-DOCK-102, SC-DOCK-136, SC-DOCK-137

### DOCK-005: No Health Check for Backend Services in docker-compose.yml
- **Severity:** Medium
- **Confidence:** 90
- **File:** `docker-compose.yml:32`, `docker-compose.yml:53`
- **Vulnerability Type:** CWE-693 (Protection Mechanism Failure)
- **Description:** The `backend` and `backend2` services have no healthcheck defined, despite being used with `gwaf.*` labels for upstream routing. The `guardianwaf` service uses `depends_on: backend` but cannot verify backend health.
- **Impact:** GuardianWAF may route traffic to unhealthy backend containers if health checks are not properly configured.
- **Remediation:** Add health checks to backend services:
  ```yaml
  healthcheck:
    test: ["CMD", "wget", "-q", "--spider", "http://localhost:3000/healthz"]
    interval: 10s
    timeout: 5s
    retries: 3
    start_period: 5s
  ```
- **References:** SC-DOCK-024, SC-DOCK-103

### DOCK-006: Missing Health Check in examples/sidecar/docker-compose.yml (app service)
- **Severity:** Medium
- **Confidence:** 90
- **File:** `examples/sidecar/docker-compose.yml:64`
- **Vulnerability Type:** CWE-693 (Protection Mechanism Failure)
- **Description:** The `app` service (backend) has a health check defined, but the `guardianwaf` service uses `depends_on: app` without `condition: service_healthy`, so it will start before the app is ready.
- **Impact:** Race condition where GuardianWAF starts before the backend is ready, potentially failing initial requests.
- **Remediation:** Change `depends_on` to:
  ```yaml
  depends_on:
    app:
      condition: service_healthy
  ```
- **References:** SC-DOCK-103

### DOCK-007: Missing Security Options in examples/sidecar/docker-compose.yml
- **Severity:** Medium
- **Confidence:** 100
- **File:** `examples/sidecar/docker-compose.yml:42`
- **Vulnerability Type:** CWE-250 (Execution with Unnecessary Privileges)
- **Description:** The `guardianwaf` service has resource limits but lacks `security_opt: no-new-privileges:true` and `cap_drop: ALL`. The `app` service has no security options at all.
- **Impact:** Containers retain default Linux capabilities. A compromise could allow privilege escalation.
- **Remediation:** Add to the guardianwaf service:
  ```yaml
  security_opt:
    - no-new-privileges:true
  cap_drop:
    - ALL
  ```
  And add a non-root user to the app service.
- **References:** SC-DOCK-046, SC-DOCK-048, SC-DOCK-100, SC-DOCK-101

### DOCK-008: Base Image Not Pinned to Digest in docker-compose.test.yml
- **Severity:** Medium
- **Confidence:** 100
- **File:** `docker-compose.test.yml:9`
- **Vulnerability Type:** CWE-829 (Reliance on Untrusted Inputs)
- **Description:** The `backend` service uses `golang:1.25-alpine` without a SHA256 digest. The main `Dockerfile` correctly uses `alpine:3.21.3`, but other compose files use un-pinned tags.
- **Impact:** The image tag could be updated to a different image with the same tag, leading to unpredictable behavior or potential compromise.
- **Remediation:** Pin to digest: `golang:1.25-alpine@sha256:abc123...`
- **References:** SC-DOCK-003, SC-DOCK-036

### DOCK-009: docker-compose.prod.yml Incomplete Production Configuration
- **Severity:** Medium
- **Confidence:** 80
- **File:** `docker-compose.prod.yml:1`
- **Vulnerability Type:** CWE-250 (Execution with Unnecessary Privileges)
- **Description:** The `docker-compose.prod.yml` override file is minimal and lacks security hardening. It only contains a partial `guardianwaf` service definition with commented-out TLS and socket options. When combined with the base `docker-compose.yml`, the resulting configuration lacks security hardening.
- **Impact:** Production deployment inherits all the security gaps from the base compose file (no resource limits, no security options, runs as root).
- **Remediation:** Add complete security hardening to `docker-compose.prod.yml`:
  ```yaml
  security_opt:
    - no-new-privileges:true
  cap_drop:
    - ALL
  read_only: true
  tmpfs:
    - /tmp
  deploy:
    resources:
      limits:
        memory: 512M
        cpus: 1.0
  user: "1000:1000"
  ```
- **References:** SC-DOCK-046, SC-DOCK-047, SC-DOCK-048, SC-DOCK-100, SC-DOCK-101, SC-DOCK-102, SC-DOCK-109

---

## Positive Findings (Good Security Practices)

1. **Multi-stage builds used in both Dockerfiles** (SC-DOCK-010) — Build dependencies are excluded from production images.

2. **Non-root user `guardianwaf` created and used in both Dockerfiles** (SC-DOCK-021) — The main Dockerfile and sidecar Dockerfile correctly create and switch to a non-root user.

3. **Docker socket NOT mounted in production compose** (SC-DOCK-057) — `docker-compose.prod.yml` explicitly comments out the socket mount and recommends TLS-based Docker client instead. The code in `internal/docker/client.go` provides `NewTLSClient()` for this purpose.

4. **Command injection prevention in Docker client** — `internal/docker/client.go` implements `isSafeContainerRef()` which validates container IDs/names and prevents shell metacharacter injection when calling `docker inspect`.

5. **`.dockerignore` properly excludes sensitive files** (SC-DOCK-026) — Excludes `.env`, `.git`, `*.pem`, `*.key`, `*.md`, and other sensitive files from the build context.

6. **TLS-based Docker client available** — `NewTLSClient()` in `internal/docker/client.go` provides a secure alternative to socket mounting for Docker daemon communication.

7. **Resource limits defined in examples/sidecar/docker-compose.yml** (SC-DOCK-102) — `guardianwaf` service has `memory: 128M` and `cpus: 0.5` limits.

8. **Health checks present in main Dockerfile** (SC-DOCK-024) — `HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3`.

9. **Uses `alpine:3.21.3` (specific version, not `latest`)** in the main Dockerfile — Good practice for reproducibility.

---

## Risk Assessment

| Area | Risk Level | Notes |
|------|------------|-------|
| Dockerfile (main) | Low | Well-hardened with multi-stage build, non-root user, health check |
| Dockerfile (sidecar) | Low | Similar hardening to main Dockerfile |
| docker-compose.yml (dev) | High | Missing resource limits, security options, runs as root |
| docker-compose.test.yml | High | Runs as root, no security options |
| docker-compose.prod.yml | Medium | Incomplete override; relies on base compose which has gaps |
| examples/sidecar/docker-compose.yml | Medium | Resource limits present, but missing security options and runs as root |
| Docker integration code | Low | Good command injection prevention, TLS client available |

---

## Recommendations (Priority Order)

1. **Add resource limits to `docker-compose.yml`** — All services need `deploy.resources.limits` to prevent resource exhaustion.
2. **Add `security_opt: no-new-privileges:true` and `cap_drop: ALL`** to all compose files — Production-grade security requires dropping all capabilities.
3. **Pin images to SHA256 digests** in compose files — Replace `latest` and version-only tags with full digests.
4. **Specify non-root users** in all compose services — Add `user: "1000:1000"` or similar to override the default root user.
5. **Complete `docker-compose.prod.yml`** — Merge security hardening from base compose to ensure production deployments are properly secured.
6. **Add health checks to backend services** in `docker-compose.yml` — Backend services should have health checks for proper service dependency ordering.
