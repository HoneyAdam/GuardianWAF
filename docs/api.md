# GuardianWAF API Documentation

## Overview

GuardianWAF provides a comprehensive REST API for programmatic control and monitoring. All API endpoints are available under `/api/v1/` and require authentication via API key header.

## Authentication

All API endpoints (except health check) require authentication using the `X-API-Key` header:

```http
X-API-Key: your-api-key-here
```

## Base URL

```
http://localhost:9443/api/v1
```

## Response Format

All responses are JSON with the following structure:

```json
{
  "status": "ok",
  "data": { ... }
}
```

Error responses:

```json
{
  "error": "Error message description"
}
```

---

## Endpoints

### Health & Status

#### GET `/health`

Health check endpoint (no authentication required).

**Response:**
```json
{
  "status": "healthy",
  "version": "dev",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

#### GET `/stats`

Get WAF statistics.

**Response:**
```json
{
  "total_requests": 1000,
  "blocked_requests": 50,
  "challenged_requests": 25,
  "logged_requests": 75,
  "passed_requests": 850,
  "avg_latency_us": 150,
  "alerting": {
    "sent": 10,
    "failed": 0,
    "webhook_count": 2,
    "email_count": 1
  }
}
```

---

### Events

#### GET `/events`

Query security events with filters.

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `limit` | int | Max results (default: 50, max: 1000) |
| `offset` | int | Pagination offset |
| `action` | string | Filter by action (block, challenge, log, pass) |
| `client_ip` | string | Filter by IP address |
| `path` | string | Filter by path prefix |
| `min_score` | int | Minimum threat score |
| `since` | string | ISO 8601 timestamp |
| `until` | string | ISO 8601 timestamp |
| `sort_by` | string | Sort field (timestamp, score) |
| `sort_order` | string | asc or desc |

**Response:**
```json
{
  "events": [
    {
      "id": "evt-123456",
      "timestamp": "2024-01-15T10:30:00Z",
      "request_id": "req-789",
      "client_ip": "192.168.1.1",
      "method": "GET",
      "path": "/api/users",
      "action": "block",
      "score": 85,
      "findings": [
        {
          "detector": "sqli",
          "category": "injection",
          "severity": "critical",
          "score": 50,
          "description": "SQL injection detected"
        }
      ]
    }
  ],
  "total": 150,
  "limit": 50,
  "offset": 0
}
```

#### GET `/events/{id}`

Get single event details.

**Response:**
```json
{
  "id": "evt-123456",
  "timestamp": "2024-01-15T10:30:00Z",
  ...
}
```

#### GET `/events/export`

Export events to JSON or CSV.

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `format` | string | `json` or `csv` (default: json) |
| `limit` | int | Max results (default: 10000, max: 50000) |
| `action` | string | Filter by action |
| `client_ip` | string | Filter by IP |
| `min_score` | int | Minimum score |
| `since` | string | ISO 8601 timestamp |
| `until` | string | ISO 8601 timestamp |

---

### Configuration

#### GET `/config`

Get current WAF configuration.

**Response:**
```json
{
  "mode": "enforce",
  "listen": ":8088",
  "waf": {
    "detection": {
      "enabled": true,
      "threshold": {
        "block": 50,
        "log": 25
      }
    },
    "rate_limit": {
      "enabled": true
    }
  },
  "dashboard": {
    "enabled": true,
    "listen": ":9443"
  },
  "alerting": {
    "enabled": true,
    "webhooks": [...],
    "emails": [...]
  }
}
```

#### PUT `/config`

Update WAF configuration.

**Request Body:**
```json
{
  "mode": "enforce",
  "waf": {
    "detection": {
      "enabled": true,
      "threshold": {
        "block": 60
      }
    }
  }
}
```

---

### Alerting

#### GET `/alerting/status`

Get alerting status and statistics.

**Response:**
```json
{
  "enabled": true,
  "webhook_count": 2,
  "email_count": 1,
  "sent": 50,
  "failed": 2,
  "webhooks": [
    {
      "name": "slack-alerts",
      "url": "https://hooks.slack.com/...",
      "type": "slack",
      "events": ["block"],
      "min_score": 50,
      "cooldown": "30s"
    }
  ],
  "emails": [
    {
      "name": "admin-alerts",
      "smtp_host": "smtp.gmail.com",
      "smtp_port": 587,
      "from": "alerts@example.com",
      "to": ["admin@example.com"],
      "use_tls": true
    }
  ]
}
```

#### GET `/alerting/webhooks`

List configured webhooks.

#### POST `/alerting/webhooks`

Add new webhook target.

**Request Body:**
```json
{
  "name": "slack-alerts",
  "url": "https://hooks.slack.com/services/...",
  "type": "slack",
  "events": ["block", "challenge"],
  "min_score": 50,
  "cooldown": "30s"
}
```

#### DELETE `/alerting/webhooks/{name}`

Remove webhook target.

#### GET `/alerting/emails`

List configured email targets.

#### POST `/alerting/emails`

Add new email target.

**Request Body:**
```json
{
  "name": "admin-alerts",
  "smtp_host": "smtp.gmail.com",
  "smtp_port": 587,
  "username": "user",
  "password": "pass",
  "from": "alerts@example.com",
  "to": ["admin@example.com", "security@example.com"],
  "use_tls": true,
  "events": ["block"],
  "min_score": 50,
  "cooldown": "5m",
  "subject": "[GuardianWAF] Security Alert"
}
```

#### DELETE `/alerting/emails/{name}`

Remove email target.

#### POST `/alerting/test`

Send test alert to target.

**Request Body:**
```json
{
  "target": "slack-alerts"
}
```

---

### IP ACL

#### GET `/ipacl`

Get whitelist and blacklist.

**Response:**
```json
{
  "whitelist": ["192.168.1.0/24", "10.0.0.0/8"],
  "blacklist": ["1.2.3.4", "5.6.7.8/32"]
}
```

#### POST `/ipacl`

Add IP to whitelist or blacklist.

**Request Body:**
```json
{
  "list": "blacklist",
  "ip": "1.2.3.4"
}
```

#### DELETE `/ipacl`

Remove IP from list.

**Request Body:**
```json
{
  "list": "blacklist",
  "ip": "1.2.3.4"
}
```

---

### Temporary Bans

#### GET `/bans`

Get active temporary bans.

**Response:**
```json
{
  "bans": [
    {
      "ip": "1.2.3.4",
      "reason": "rate limit exceeded",
      "expires_at": "2024-01-15T11:30:00Z",
      "count": 1
    }
  ]
}
```

#### POST `/bans`

Add temporary ban.

**Request Body:**
```json
{
  "ip": "1.2.3.4",
  "duration": "1h",
  "reason": "manual ban"
}
```

#### DELETE `/bans`

Remove ban.

**Request Body:**
```json
{
  "ip": "1.2.3.4"
}
```

---

### Custom Rules

#### GET `/rules`

Get custom rules.

#### POST `/rules`

Add custom rule.

**Request Body:**
```json
{
  "name": "Block SQLMap",
  "enabled": true,
  "priority": 100,
  "conditions": [
    {
      "field": "user_agent",
      "op": "contains",
      "value": "sqlmap"
    }
  ],
  "action": "block",
  "score": 100
}
```

#### PUT `/rules/{id}`

Update rule.

#### DELETE `/rules/{id}`

Delete rule.

---

### Routing

#### GET `/routing`

Get routing configuration.

**Response:**
```json
{
  "upstreams": [
    {
      "name": "api",
      "load_balancer": "weighted",
      "targets": [
        {"url": "http://api1:3000", "weight": 3},
        {"url": "http://api2:3000", "weight": 1}
      ],
      "health_check": {
        "enabled": true,
        "interval": "10s",
        "timeout": "5s",
        "path": "/healthz"
      }
    }
  ],
  "virtual_hosts": [...],
  "routes": [...]
}
```

#### PUT `/routing`

Update routing configuration.

---

### Upstreams

#### GET `/upstreams`

Get upstream health status.

**Response:**
```json
[
  {
    "name": "api",
    "strategy": "weighted",
    "targets": [
      {
        "url": "http://api1:3000",
        "healthy": true,
        "circuit_state": "closed",
        "active_conns": 5,
        "weight": 3
      }
    ],
    "healthy_count": 1,
    "total_count": 2
  }
]
```

---

### GeoIP

#### GET `/geoip/lookup`

Lookup IP geolocation.

**Query Parameters:**
- `ip`: IP address to lookup

**Response:**
```json
{
  "ip": "1.2.3.4",
  "country": "US",
  "name": "United States"
}
```

---

### Logs

#### GET `/logs`

Get application logs.

**Query Parameters:**
- `level`: Filter by level (debug, info, warn, error)
- `limit`: Max entries (default: 100)

**Response:**
```json
{
  "logs": [
    {
      "time": "2024-01-15T10:30:00Z",
      "level": "info",
      "message": "WAF started"
    }
  ],
  "total": 150
}
```

---

### AI Analysis

#### GET `/ai/providers`

Get available AI providers.

#### GET `/ai/config`

Get AI configuration.

#### PUT `/ai/config`

Update AI configuration.

#### GET `/ai/history`

Get analysis history.

#### GET `/ai/stats`

Get AI usage statistics.

---

### SSE (Server-Sent Events)

#### GET `/sse`

Real-time event stream.

**Headers:**
```http
Accept: text/event-stream
X-API-Key: your-api-key
```

**Events:**
- `connected`: Connection established
- `event`: WAF security event

---

## Error Codes

| Status | Description |
|--------|-------------|
| 400 | Bad Request - Invalid parameters |
| 401 | Unauthorized - Missing or invalid API key |
| 403 | Forbidden - Action not allowed |
| 404 | Not Found - Resource doesn't exist |
| 429 | Too Many Requests - Rate limited |
| 500 | Internal Server Error |

---

## Rate Limiting

API endpoints are rate-limited per IP. Default limits:
- 1000 requests per minute
- Burst: 100 requests

---

## CORS

API supports CORS for cross-origin requests:

```
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, PUT, POST, DELETE, OPTIONS
Access-Control-Allow-Headers: Content-Type, X-API-Key
```
