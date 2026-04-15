# Docker Security Scan Results

**Target:** GuardianWAF (Pure Go WAF)
**Date:** 2026-04-15

---

## Summary

| Category | Finding | Severity |
|----------|---------|----------|
| Docker Socket Mount | Production compose mounts Docker socket | MEDIUM |
| Image Tag | `:latest` tag used in compose files | LOW |
| Non-root User | Both Dockerfiles run as non-root | PASS |

---

### [MEDIUM] Docker Socket Mounted in Production

- **Category:** Docker Security
- **Location:** docker-compose.yml:14
- **Description:** The production `docker-compose.yml` mounts the Docker socket as a volume (`/var/run/docker.sock:/var/run/docker.sock:ro`). This is the primary mechanism for Docker auto-discovery, but mounting the Docker socket into a container is a well-known privilege escalation vector. Any process inside the container with access to the socket can communicate with the host Docker daemon, potentially escaping the container and gaining full host access.

- **Remediation:** The Docker auto-discovery feature intentionally requires socket access to discover other containers. For production deployments:
  1. Use the TLS-based Docker client (`NewTLSClient`) instead of socket mounting — the codebase already supports this via `internal/docker/client.go` TLSConfig
  2. Alternatively, disable Docker auto-discovery and use static configuration or label-based routing without socket access
  3. If socket mount is required, restrict it to development/staging environments only and document the security trade-off clearly

---

### [LOW] Use of `:latest` Image Tag

- **Category:** Image Pull Policy
- **Location:** docker-compose.yml:6, examples/sidecar/docker-compose.yml:7
- **Description:** Both compose files reference `ghcr.io/guardianwaf/guardianwaf:latest`. Using the `:latest` tag means updates to the image (including breaking changes or vulnerability patches) are picked up automatically on container restart, which can cause unpredictable behavior. Production deployments should pin to a specific version tag.

- **Remediation:** Use a specific version tag in production, e.g., `ghcr.io/guardianwaf/guardianwaf:v1.2.3`. The Dockerfile already supports an `IMAGE_VERSION` build arg — leverage this to embed the version at build time and reference it in the compose file.

---

## Passed Checks

| Check | Details |
|-------|---------|
| Non-root User (main Dockerfile) | Line 61: `USER guardianwaf` — runtime runs as `guardianwaf` unprivileged user |
| Non-root User (sidecar Dockerfile) | Line 14: `USER guardianwaf` — sidecar runs as `guardianwaf` unprivileged user |
| Privileged Containers | No `privileged: true` found in any Docker configuration |
| Secrets in Compose | No hardcoded secrets (passwords, API keys, tokens) found in docker-compose files |
| Docker Daemon Communication | Unix socket is read-only (`:ro` flag on socket mount); direct TCP not used |
| Container Escape | Only socket and config files mounted; no host path mounts that could enable escape |

---

## Notes

- **Docker auto-discovery design:** The socket mount exists specifically to enable GuardianWAF's container auto-discovery feature (watching for `gwaf.*` labels on other containers). This is documented behavior.
- **TLS client available:** The codebase already provides `NewTLSClient` in `internal/docker/client.go` as a secure alternative to socket mounting for remote Docker daemon connections.
- **docker-compose.test.yml** is a test-only file and is not subject to production hardening requirements.
