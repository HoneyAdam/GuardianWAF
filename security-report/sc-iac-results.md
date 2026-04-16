# Infrastructure as Code Security Scan Results

**Scanner:** sc-iac (IaC Security Scanner)
**Target:** GuardianWAF Repository
**Date:** 2026-04-16
**Files Scanned:**
- Kubernetes manifests: `examples/kubernetes/`, `contrib/k8s/`
- GitHub Actions workflows: `.github/workflows/ci.yml`, `release.yml`, `website.yml`

---

## Summary

| Category | High | Medium | Low | Info |
|----------|------|--------|-----|------|
| Kubernetes | 2 | 3 | 4 | 0 |
| GitHub Actions | 1 | 2 | 3 | 0 |
| **Total** | **3** | **5** | **7** | **0** |

---

## Critical Findings

### [CRITICAL-1] Container Image Tag `latest` Used in Kubernetes Deployments

**Severity:** High
**Files:**
- `examples/kubernetes/deployment.yaml` (line 20)
- `examples/kubernetes/sidecar-deployment.yaml` (line 21)
- `contrib/k8s/deployment.yaml` (line 19)

**Description:** Using the `latest` tag for container images is a security anti-pattern. The `latest` tag does not provide deterministic deployments and can lead to unexpected updates in production.

**Recommendation:** Use specific version tags (e.g., `ghcr.io/guardianwaf/guardianwaf:v1.2.3`) or commit SHA references for immutable deployments.

**Example fix:**
```yaml
image: ghcr.io/guardianwaf/guardianwaf:v1.0.0  # Use semantic version
```

---

## High Findings

### [HIGH-1] TLS Disabled in Production ConfigMap

**Severity:** High
**File:** `contrib/k8s/configmap.yaml`
**Line:** 11-12

**Description:** TLS is explicitly disabled in the contrib/k8s configmap:
```yaml
tls:
  enabled: false
```

**Recommendation:** Enable TLS for all production deployments. TLS should be mandatory for the dashboard and any API endpoints handling sensitive data.

---

### [HIGH-2] Missing Resource Limits in Sidecar Container

**Severity:** High
**File:** `examples/kubernetes/sidecar-deployment.yaml`

**Description:** The sidecar GuardianWAF container has no resource limits defined:
```yaml
resources:
  limits:
    memory: "64Mi"
    cpu: "200m"
```
However, the main app container has no resource constraints at all.

**Recommendation:** Add explicit resource requests and limits to all containers to prevent resource exhaustion attacks.

---

### [HIGH-3] Action Not Pinned to GitHub Actions SHA

**Severity:** High
**Files:**
- `.github/workflows/ci.yml` (line 97)
- `.github/workflows/release.yml` (lines 40, 90, 97, 100)
- `.github/workflows/website.yml` (lines 39, 46, 59)

**Description:** GitHub Actions are using floating version references (e.g., `@v6`, `@v7`, `@v4`) instead of pinned SHA hashes. This creates a supply chain vulnerability where action authors could push malicious changes to the major version tag.

**Recommendation:** Pin actions to specific SHA commits using the full 40-character SHA hash. Example:
```yaml
uses: goreleaser/goreleaser-action@b4b9c9f8e8a3c68c3c3c3c3c3c3c3c3c3c3c3c3c
```

---

## Medium Findings

### [MED-1] Missing `automountServiceAccountToken` Setting

**Severity:** Medium
**Files:** All Kubernetes deployment manifests

**Description:** The deployments do not explicitly set `automountServiceAccountToken: false`. If a ServiceAccount is automatically mounted, the pod can access the Kubernetes API.

**Recommendation:** Add to pod spec:
```yaml
spec:
  automountServiceAccountToken: false
```

---

### [MED-2] GitHub Token with Write Permissions in Release Workflow

**Severity:** Medium
**File:** `.github/workflows/release.yml`
**Line:** 7-9

**Description:** The release workflow has broad permissions:
```yaml
permissions:
  contents: write
  packages: write
```

**Recommendation:** Apply principle of least privilege. For package publishing, `packages: write` is necessary, but consider if `contents: write` is needed beyond the release tag creation.

---

### [MED-3] Missing Security Context in Some Deployments

**Severity:** Medium
**File:** `contrib/k8s/deployment.yaml`

**Description:** The contrib/k8s deployment lacks explicit security context settings that are present in `examples/kubernetes/deployment.yaml`:
```yaml
# Missing from contrib/k8s/deployment.yaml:
securityContext:
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  runAsNonRoot: true
  runAsUser: 1000
  capabilities:
    drop:
      - ALL
```

**Recommendation:** Apply consistent security context across all deployment manifests.

---

### [MED-4] No ImagePullSecrets for GHCR

**Severity:** Medium
**Files:** All Kubernetes deployment manifests

**Description:** The deployments pull from `ghcr.io/guardianwaf/guardianwaf` without an `imagePullSecrets` reference. For private registries, this would fail.

**Recommendation:** If using a private registry, add:
```yaml
imagePullSecrets:
  - name: ghcr-secret
```

---

### [MED-5] Goreleaser Action Uses Latest Version

**Severity:** Medium
**File:** `.github/workflows/release.yml`
**Line:** 43

**Description:** Goreleaser action uses `version: latest`:
```yaml
uses: goreleaser/goreleaser-action@v6
  with:
    distribution: goreleaser
    version: latest
```

**Recommendation:** Pin to a specific version tag or SHA.

---

## Low Findings

### [LOW-1] Example Domains Not Updated

**Severity:** Low
**Files:** `examples/kubernetes/configmap.yaml`, `examples/kubernetes/ingress.yaml`

**Description:** Uses placeholder domains like `waf.example.com`, `dashboard.example.com`. While acceptable for examples, these should be clearly marked as placeholders in documentation.

---

### [LOW-2] Liveness Probe Points to Dashboard Port

**Severity:** Low
**File:** `contrib/k8s/deployment.yaml`

**Description:** Liveness probe is on port 9443 (dashboard) instead of the WAF HTTP port 8088:
```yaml
livenessProbe:
  httpGet:
    path: /healthz
    port: 9443  # Should this be 8088?
```

**Note:** This may be intentional if the dashboard is the primary health endpoint.

---

### [LOW-3] Optional TLS Certificate May Cause Issues

**Severity:** Low
**File:** `contrib/k8s/deployment.yaml`
**Line:** 60

**Description:** TLS cert is marked `optional: false`, which means the pod will not start if the certificate secret doesn't exist:
```yaml
- name: tls-cert
  secret:
    secretName: guardianwaf-tls
    optional: false  # Will fail if cert not issued yet
```

**Recommendation:** Consider using `optional: true` during initial deployment, or ensure cert-manager has issued the certificate before deploying.

---

### [LOW-4] No Pod Disruption Budget

**Severity:** Low
**Files:** All Kubernetes deployment manifests

**Description:** With `replicas: 2`, there is no PodDisruptionBudget to ensure high availability during node drains.

**Recommendation:** Add a PDB:
```yaml
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: guardianwaf-pdb
spec:
  minAvailable: 1
  selector:
    matchLabels:
      app: guardianwaf
```

---

### [LOW-5] No NetworkPolicy Defined

**Severity:** Low
**Files:** All Kubernetes deployment manifests

**Description:** No NetworkPolicy restricts traffic flow between pods.

**Recommendation:** Implement NetworkPolicies to restrict traffic to only necessary paths.

---

### [LOW-6] Missing Vertical Pod Autoscaler

**Severity:** Low
**Files:** All Kubernetes deployment manifests

**Description:** No VPA resource to automatically adjust container resource requests based on actual usage.

---

### [LOW-7] No Pod Topology Spread Constraints

**Severity:** Low
**Files:** All Kubernetes deployment manifests

**Description:** While `podAntiAffinity` is used, there are no explicit `topologySpreadConstraints` for more sophisticated distribution.

---

## Positive Security Practices Found

The following good security practices were observed:

1. **Security context in examples/kubernetes/deployment.yaml:**
   - `allowPrivilegeEscalation: false`
   - `readOnlyRootFilesystem: true`
   - `runAsNonRoot: true`
   - `capabilities.drop: ALL`

2. **Dashboard authentication via ingress** (examples/kubernetes/sidecar-deployment.yaml):
   - Uses `nginx.ingress.kubernetes.io/auth-type: basic`
   - References auth secret for protection

3. **Principle of least privilege in website workflow:**
   ```yaml
   permissions:
     contents: read
     pages: write
     id-token: write
   ```

4. **Cert-manager integration** for automatic TLS certificate management via ACME.

5. **SBOM generation** in release workflow for supply chain transparency.

---

## Recommendations Summary

### Immediate Actions
1. Replace all `latest` image tags with specific version tags or commit SHAs
2. Enable TLS in production configurations
3. Pin GitHub Actions to SHA commits

### Short-term Actions
4. Add resource limits to all containers
5. Apply consistent security context across all deployments
6. Add `automountServiceAccountToken: false` to pod specs

### Long-term Improvements
7. Add PodDisruptionBudgets for HA
8. Implement NetworkPolicies
9. Add vulnerability scanning for container images
10. Enable supply chain security features (sigstore, SLSA)

---

*Generated by sc-iac - IaC Security Scanner*
