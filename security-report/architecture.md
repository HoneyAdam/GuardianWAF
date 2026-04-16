# GuardianWAF Security Architecture Report

## 1. Technology Stack Detection

### Languages Detected

| Language | Files | Lines of Code | Percentage |
|----------|-------|---------------|------------|
| Go | 339 | 7,177 | ~73% |
| TypeScript/React | ~30 (website/src) | 2,624 | ~27% |

### Primary Language: Go (1.25+)
- **Module**: `github.com/guardianwaf/guardianwaf`
- **Location**: `D:/CODEBOX/PROJECTS/GuardianWAF/go.mod`
- **Key Constraint**: Zero external Go dependencies (only stdlib + optional quic-go for HTTP/3)

### Secondary Language: TypeScript/React
- **Purpose**: React dashboard (Vite + TailwindCSS)
- **Location**: `D:/CODEBOX/PROJECTS/GuardianWAF/website/src`
- **Embedded**: Built React dashboard is embedded into Go binary at `internal/dashboard/dist/`

### Go Dependencies
```
github.com/quic-go/quic-go v0.59.0  (optional HTTP/3 support, build with -tags http3)
```

---

## 2. Application Type Classification

GuardianWAF is a **zero-dependency Web Application Firewall (WAF)** written in Go that functions as:

1. **Reverse Proxy** (`internal/proxy/`) - Load balancing, health checks, circuit breaker
2. **Security Gateway** - 25+ security layers processing requests through a pipeline
3. **API Server** - Built-in dashboard (React), MCP server (JSON-RPC 2.0)
4. **Multi-Tenant Platform** (`internal/tenant/`) - Per-tenant isolation and billing

### Core Package Layout
```
cmd/guardianwaf/       - CLI entry point (serve, sidecar, check, validate)
internal/engine/       - Core WAF engine, pipeline, context, scoring
internal/layers/       - 25+ security layers (detection, mitigation, etc.)
internal/config/       - Configuration management
internal/proxy/        - Reverse proxy with load balancing
internal/dashboard/    - React dashboard + REST API
internal/mcp/          - Model Context Protocol JSON-RPC server
internal/cluster/      - Distributed mode (gossip + leader election)
internal/clustersync/  - Cross-node state synchronization
internal/tenant/       - Multi-tenancy management
```

---

## 3. Entry Points Mapping

### HTTP Routes

#### Main WAF Proxy (`cmd/guardianwaf/main_default.go`)
- All incoming traffic passes through WAF middleware first

#### Dashboard API (`internal/dashboard/dashboard.go`)
- **Auth**: `POST /login`, `GET /logout` - Session-based auth with HMAC-signed cookies
- **Events**: `GET /api/events`, `GET /api/events/stats`
- **Config**: `GET/PUT /api/config`, `POST /api/reload`
- **Tenants**: `GET/POST /api/tenants`, `GET/PUT/DELETE /api/tenants/{id}`
- **Rules**: `GET/POST /api/rules`, `GET/PUT/DELETE /api/rules/{id}`
- **IP ACL**: `GET/POST /api/ip-acl`, `DELETE /api/ip-acl/{ip}`
- **Stats**: `GET /api/stats`, `GET /api/stats/top-ips`

#### MCP Server (`internal/mcp/server.go`)
- **Transport**: stdio (JSON-RPC 2.0) or HTTP SSE
- **44 tools** including: `get_stats`, `get_events`, `add_blacklist`, `remove_whitelist`, `add_rate_limit`, etc.
- **Auth**: Optional API key via `initialize` request

#### Cluster Sync (`internal/clustersync/handlers.go`)
- `GET /api/cluster/health` - Node health status
- `POST /api/cluster/sync` - Receive sync events
- `GET /api/cluster/events` - Query events since timestamp
- `GET /api/clusters` - List cluster configurations
- **Auth**: HMAC-based shared secret validation

#### Docker Auto-Discovery (`internal/docker/discovery.go`)
- Watches Docker daemon for containers with `gwaf.*` labels
- **Socket**: Unix socket (Linux) or named pipe (Windows) or Docker CLI

### CLI Commands (`cmd/guardianwaf/main.go`)
```
guardianwaf serve     - Full reverse proxy mode with dashboard
guardianwaf sidecar  - Lightweight sidecar (no dashboard/MCP)
guardianwaf check    - Dry-run request test
guardianwaf validate - Config file validation
guardianwaf test-alert - Test alert delivery
```

### WebSocket Support (`internal/layers/websocket/`)
- WebSocket handshake validation
- Per-IP connection limits
- Frame size limits and payload scanning

---

## 4. Data Flow Map

### Request Processing Pipeline

```
HTTP Request
    │
    ▼
┌─────────────────────────────────────────────────────────────┐
│ AcquireContext() - sync.Pool allocation                     │
│ - Parse HTTP request components                            │
│ - Extract client IP (trusted proxy support)                 │
│ - Read/decompress body (gzip/deflate, max 100:1 ratio)     │
│ - Populate JA4 TLS fingerprint fields                       │
│ - Initialize ScoreAccumulator                               │
└─────────────────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────────────────┐
│ Pipeline.Execute() - Ordered layers (lowest Order first)    │
│                                                                 │
│ Order 1:    SIEM           - Passive event forwarding          │
│ Order 75:   Cluster        - Gossip + leader election          │
│ Order 76:   WebSocket      - WebSocket validation              │
│ Order 78:   gRPC           - gRPC method allowlist             │
│ Order 95:   Canary         - Traffic splitting                 │
│ Order 100:  IP ACL         - CIDR whitelist/blacklist         │
│ Order 125:  Threat Intel   - IP/domain reputation feeds        │
│ Order 140:  Cache          - Response caching                   │
│ Order 145:  Replay         - Request/response recording        │
│ Order 150:  CORS           - Origin validation                 │
│ Order 150:  Custom Rules   - Geo-aware rule engine             │
│ Order 200:  Rate Limit     - Token bucket (auto-ban)          │
│ Order 250:  ATO Protection  - Brute force, credential stuffing │
│ Order 275:  API Security   - JWT validation, API key auth      │
│ Order 280:  API Validation - OpenAPI schema validation         │
│ Order 285:  GraphQL        - Query depth/complexity limits     │
│ Order 300:  Sanitizer      - Normalize + validate requests     │
│ Order 310:  API Discovery  - Passive endpoint discovery         │
│ Order 350:  CRS            - OWASP ModSecurity CRS parser       │
│ Order 400:  Detection      - 6 detectors (sqli, xss, lfi,     │
│                              cmdi, xxe, ssrf)                   │
│ Order 430:  JS Challenge    - SHA-256 proof-of-work             │
│ Order 450:  Virtual Patch  - CVE-based patching                 │
│ Order 473:  ML Anomaly     - ONNX Isolation Forest              │
│ Order 475:  DLP            - Credit cards, SSNs, PII            │
│ Order 480:  AI Remediation - Generated rules from AI verdicts   │
│ Order 500:  Bot Detection   - JA3/JA4 fingerprinting, UA,        │
│                              behavioral analysis                │
│ Order 590:  Client-Side    - CSP injection, Magecart detection  │
│ Order 600:  Response       - Security headers, data masking     │
└─────────────────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────────────────┐
│ Short-circuit on ActionBlock                                 │
│ - Score accumulation via ScoreAccumulator                     │
│ - Findings collection per detector                            │
└─────────────────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────────────────┐
│ Proxy to upstream (if Pass/Log)                              │
│ internal/proxy/ - Reverse proxy with circuit breaker,        │
│ health checks, load balancing (round_robin, weighted,        │
│ least_conn, ip_hash)                                        │
└─────────────────────────────────────────────────────────────┘
```

### Request Context Fields (`internal/engine/context.go`)
```
RequestContext:
  - Request *http.Request
  - ClientIP net.IP
  - Method, URI, Path, QueryParams, Headers, Cookies, Body
  - Normalized versions (after Sanitizer at Order 300)
  - Accumulator *ScoreAccumulator, Action Action
  - RequestID string (UUID via crypto/rand)
  - TLSVersion, TLSCipherSuite, JA4* fields (TLS fingerprinting)
  - TenantID, TenantWAFConfig *config.WAFConfig
```

---

## 5. Trust Boundaries

### Authentication (`internal/layers/apisecurity/`, `internal/dashboard/auth.go`)

#### JWT Validation (`internal/layers/apisecurity/jwt.go`)
- **Algorithms**: RS256, ES256, HS256 (configurable allowlist)
- **JWKS URL fetching** with SSRF protection (rejects private network IPs)
- **Claims validation**: iss, aud, exp, nbf, iat
- **Multi-tenant isolation** via `tenant_id` claim

#### API Key Authentication (`internal/layers/apisecurity/apikey.go`)
- Keys stored as `sha256:hex` or `bcrypt:hash`
- Path-based restrictions per key
- Rate limiting per key
- Constant-time comparison for hash validation
- **No API keys in query parameters** (rejected, logs warning)

#### Dashboard Session Management (`internal/dashboard/auth.go`)
- **HMAC-signed session tokens** (SHA-256)
- **IP binding** - tokens bound to client IP
- **Sliding expiry**: 24-hour max session age
- **Absolute expiry**: 7-day hard limit
- **Concurrent session limit**: 5 per IP (oldest evicted)
- **Session revocation** support (sync.Map storage)
- Cookie flags: `HttpOnly`, `Secure`, `SameSite=Strict`

### Rate Limiting (`internal/layers/ratelimit/ratelimit.go`)
- Token bucket algorithm
- Per-IP and per-IP+path scopes
- Auto-ban after configurable failure count
- Radix tree for efficient CIDR matching

### Input Validation (`internal/layers/sanitizer/`)
- Max URL length
- Max header count (100) and size
- Max body size with decompression bomb detection (100:1 ratio)
- Null byte blocking
- Encoding normalization
- HTTP method allowlisting

### CORS (`internal/layers/cors/`)
- Origin allowlisting
- Method and header allowlisting
- Credential validation
- Preflight caching
- Strict mode support

---

## 6. External Integrations

### Databases/Caches

#### Redis (`internal/layers/cache/`)
```yaml
Cache:
  backend: "redis"
  redis_addr: string
  redis_password: string  # Stored in config
  redis_db: int
```
- Used for response caching backend
- Optional memory backend for zero-dependency deployments

### Email/SMTP (`internal/alerting/email.go`)
```yaml
Email:
  smtp_host: string
  smtp_port: int (default 587)
  username: string
  password: string  # Stored in config
  use_tls: bool
```
- TLS 1.2+ required for SMTP connections
- **SMTP header injection prevention**: CRLF sanitization on From, To, Subject

### Third-Party APIs

#### SIEM Integration (`internal/layers/siem/`)
```yaml
SIEM:
  endpoint: string
  format: "cef" | "leef" | "json" | "splunk" | "elastic"
  api_key: string  # Stored in config
  skip_verify: bool
```
- CEF (Common Event Format), LEEF, JSON, Splunk, Elastic formats
- Batch sending with configurable size/interval

#### AI Analysis (`internal/ai/`)
```yaml
AIAnalysis:
  catalog_url: string  # models.dev catalog
  batch_size: int
  batch_interval: duration
  max_tokens_per_hour: int64
  auto_block: bool (blocks if confidence >= 70%)
```
- OpenAI-compatible API client
- Background batch processing (NOT per-request)
- Cost limits per hour/day

#### Threat Intel Feeds (`internal/layers/threatintel/`)
```yaml
ThreatIntel:
  feeds:
    - type: "file" | "url"
      path: string  # for type=file
      url: string   # for type=url
      refresh: duration
      format: "json" | "jsonl" | "csv"
```
- LRU cache for IP/domain reputation
- Configurable TTL

### Cloud Services

#### ACME/Let's Encrypt (`internal/acme/`)
```yaml
ACME:
  enabled: bool
  email: string
  domains: []string
  cache_dir: string
```
- HTTP-01 challenge for certificate issuance
- Automatic certificate renewal

### Container Orchestration

#### Docker Auto-Discovery (`internal/docker/discovery.go`)
- **Label prefix**: `gwaf.*` (configurable)
- **Socket**: Unix socket (Linux), named pipe (Windows), Docker CLI
- **Networks**: Auto-detects container IP from specified network
- **Health checks**: Configurable interval/path

---

## 7. Authentication Architecture

### JWT Flow (`internal/layers/apisecurity/jwt.go`)
```
1. Request arrives with Authorization: Bearer <token>
2. JWTValidator.Validate(token) called
3. Algorithm allowlist check (rejects unspecified algos)
4. Signature verification (RSA/ECDSA/HMAC)
5. Claims validation: exp, nbf, iat (with clock skew tolerance)
6. Issuer/Audience validation
7. JWKS refresh if kid not cached (with SSRF check)
8. Return claims or error
```

### API Key Flow (`internal/layers/apisecurity/apikey.go`)
```
1. Request arrives with X-API-Key header
2. Hash key with SHA-256
3. Lookup hash in keys map (constant-time)
4. Check key enabled
5. Check path allowed for key
6. Check rate limit not exceeded
7. Return config or error
```

### Dashboard Session Flow (`internal/dashboard/auth.go`)
```
Login:
1. POST /login with API key
2. Constant-time comparison with stored key
3. Generate HMAC-signed token (timestamp.created.sig)
4. Token includes client IP in HMAC
5. Set secure cookie with HttpOnly, SameSite=Strict

Subsequent Requests:
1. verifySession(cookie, clientIP)
2. Check not revoked (sync.Map)
3. Verify HMAC signature
4. Check sliding expiry (24h)
5. Check absolute expiry (7d)
6. Return true/false
```

### Cluster Authentication (`internal/clustersync/handlers.go`)
```
checkAuth(r):
- Extract X-Node-Secret header
- Constant-time comparison with shared_secret
- Reject if mismatch
```

---

## 8. File Structure Analysis

### Configuration
```
D:/CODEBOX/PROJECTS/GuardianWAF/
  guardianwaf.yaml          # Main configuration file
  go.mod / go.sum          # Go module definition
  internal/config/
    config.go              # All config structs (1694 lines)
```

### Docker/Deployment
```
D:/CODEBOX/PROJECTS/GuardianWAF/
  Dockerfile               # Single-stage Docker build
  docker-compose.yml       # Local development
  docker-compose.prod.yml   # Production setup
  docker-compose.test.yml   # Integration testing
  .github/workflows/       # CI/CD pipelines
```

### Sensitive Paths

| Path | Purpose | Auth |
|------|---------|------|
| `/api/cluster/*` | Cluster management | Shared secret |
| `/api/tenants` | Multi-tenant admin | Dashboard API key |
| `/api/config` | WAF configuration | Dashboard API key |
| `/metrics` | Prometheus metrics | None (internal) |
| `/healthz` | Kubernetes probe | None (internal) |
| `/api/mcp` | MCP server | Optional API key |

### Key Files

| File | Purpose |
|------|---------|
| `guardianwaf.go` | Public library API |
| `options.go` | Functional options pattern |
| `internal/engine/pipeline.go` | Layer execution engine |
| `internal/engine/context.go` | Request context (sync.Pool) |
| `internal/engine/engine.go` | WAF engine core |
| `internal/dashboard/auth.go` | Dashboard authentication |
| `internal/layers/apisecurity/jwt.go` | JWT validation |
| `internal/layers/apisecurity/apikey.go` | API key validation |
| `internal/tls/certstore.go` | TLS certificate management |
| `internal/mcp/server.go` | MCP JSON-RPC server |

---

## 9. Detected Security Controls

### WAF Core Features (Self-Referential)

| Feature | Location | Order |
|---------|----------|-------|
| SQL Injection Detection | `internal/layers/detection/sqli/` | 400 |
| XSS Detection | `internal/layers/detection/xss/` | 400 |
| LFI Detection | `internal/layers/detection/lfi/` | 400 |
| Command Injection Detection | `internal/layers/detection/cmdi/` | 400 |
| XXE Detection | `internal/layers/detection/xxe/` | 400 |
| SSRF Detection | `internal/layers/detection/ssrf/` | 400 |

### Security Headers (`internal/layers/response/`)
```yaml
SecurityHeaders:
  X-Content-Type-Options: "nosniff"
  X-Frame-Options: "DENY" | "SAMEORIGIN"
  Referrer-Policy: strict-origin-when-cross-origin
  Permissions-Policy: ...
  HSTS: (with includeSubDomains)
```

### Content Security Policy (`internal/layers/clientside/`)
- CSP header injection
- Report-only mode
- Per-directive allowlists

### Bot Detection (`internal/layers/botdetect/`)
- JA3/JA4 TLS fingerprinting
- User-Agent analysis
- Behavioral analysis
- Biometric detection (mouse/keyboard)
- Browser fingerprinting (canvas, WebGL, fonts)
- hCaptcha/Turnstile integration

### JS Challenge (`internal/layers/challenge/`)
- SHA-256 proof-of-work
- Configurable difficulty (leading zero bits)
- Cookie-based validation
- HMAC-secret signing

### DLP (`internal/layers/dlp/`)
```yaml
DLP:
  patterns:  # credit cards, SSNs, API keys, PII
  scan_request: bool
  scan_response: bool
  block_on_match: bool
  mask_response: bool
```

### Rate Limiting (`internal/layers/ratelimit/`)
- Token bucket algorithm
- Per-IP and per-path limits
- Auto-ban with TTL
- Radix tree for CIDR matching

### IP ACL (`internal/layers/ipacl/`)
- Whitelist/blacklist with CIDR support
- Radix tree for efficient matching
- Runtime add/remove via API

### Zero Trust (`internal/layers/zerotrust/`)
- mTLS requirement option
- Device attestation
- Session TTL management

---

## 10. Language Detection Summary

| Language | Type | Primary Use | LOC | % |
|----------|------|-------------|-----|---|
| Go | Compiled | WAF engine, proxy, layers, CLI | 7,177 | ~73% |
| TypeScript | Interpreted | React dashboard UI | 2,624 | ~27% |

### Build Artifacts
- `guardianwaf` (Linux x86-64 binary)
- `guardianwaf.exe` (Windows binary)
- Docker image (single-stage build)

### No External Go Dependencies
- Only Go standard library used in core
- Optional `quic-go` for HTTP/3 (build tag required)
- Frontend npm packages are isolated from Go codebase

---

## Security Architecture Highlights

### Strengths

1. **Zero-Dependency Core**: Minimal attack surface in Go code
2. **Pipeline Architecture**: Clear separation of concerns, ordered execution
3. **sync.Pool Allocation**: Zero-allocation hot paths for performance
4. **Constant-Time Comparisons**: Timing-safe authentication (HMAC, API keys)
5. **IP Binding**: Session tokens bound to client IP
6. **Trusted Proxy Support**: X-Forwarded-For only trusted from configured CIDRs
7. **SSRF Protection**: JWKS URL fetching validates against private networks
8. **SMTP Header Injection**: CRLF sanitization on all email headers
9. **Decompression Bomb Detection**: 100:1 ratio limit on decompressed content
10. **Multi-Tenant Isolation**: Per-tenant WAF config and rate tracking

### Potential Attack Surfaces

1. **MCP Server** (`/api/mcp`): JSON-RPC interface with 44 tools - requires API key protection
2. **Cluster Sync** (`/api/cluster/*`): Inter-node communication with shared secret auth
3. **Docker Discovery**: Unix socket access for container auto-discovery
4. **Dashboard**: Session-based auth with API key fallback
5. **JWKS Fetching**: External HTTP calls to third-party JWKS endpoints

### Configuration Security

- API keys stored in config file (not hardcoded)
- TLS minimum version: 1.3 for cert store
- Dashboard sessions use `Secure` cookie flag
- Rate limiting prevents brute force
