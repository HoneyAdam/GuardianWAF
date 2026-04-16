# WebSocket Security

GuardianWAF provides comprehensive WebSocket security features including handshake validation, frame inspection, rate limiting, and payload scanning.

## Features

- **Handshake Validation**: Verify WebSocket upgrade requests
- **Origin Validation**: Control allowed origins with wildcard support
- **Frame Inspection**: Parse and validate WebSocket frames
- **Rate Limiting**: Token bucket rate limiting per connection
- **Size Limits**: Configurable frame and message size limits
- **Payload Scanning**: Scan WebSocket messages for threats
- **Connection Management**: Track active connections and enforce limits
- **Idle Timeout**: Automatic cleanup of stale connections

## Configuration

```yaml
waf:
  websocket:
    enabled: true
    max_message_size: 10485760      # 10MB
    max_frame_size: 1048576         # 1MB
    rate_limit_per_second: 100
    rate_limit_burst: 50
    allowed_origins:                # Empty = same-origin policy (reject cross-origin by default)
      - "https://example.com"
      - "https://*.example.com"     # Wildcard subdomain
    blocked_extensions:
      - ".exe"
      - ".bat"
    block_empty_messages: false
    block_binary_messages: false
    max_concurrent_per_ip: 100
    handshake_timeout: 10s
    idle_timeout: 60s
    scan_payloads: true
```

## WebSocket Handshake

The layer validates WebSocket upgrade requests:

```
Client Request:
  GET /ws HTTP/1.1
  Host: server.example.com
  Upgrade: websocket
  Connection: Upgrade
  Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
  Sec-WebSocket-Version: 13
  Origin: https://example.com

Server Response:
  HTTP/1.1 101 Switching Protocols
  Upgrade: websocket
  Connection: Upgrade
  Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
```

### Validation Checks

1. **Upgrade Header**: Must contain "websocket"
2. **Connection Header**: Must contain "upgrade"
3. **Sec-WebSocket-Key**: Required for handshake
4. **Origin**: Checked against allowed origins if configured
5. **Path**: Checked for blocked extensions
6. **Connection Limit**: Enforced per IP

## Frame Structure

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-------+-+-------------+-------------------------------+
|F|R|R|R| opcode|M| Payload len |    Extended payload length    |
|I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
|N|V|V|V|       |S|             |   (if payload len==126/127)  |
| |1|2|3|       |K|             |                               |
+-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
|     Extended payload length continued, if payload len == 127  |
+ - - - - - - - - - - - - - - - +-------------------------------+
|                               |Masking-key, if MASK set to 1  |
+-------------------------------+-------------------------------+
| Masking-key (continued)       |          Payload Data         |
+-------------------------------- - - - - - - - - - - - - - - -+
:                     Payload Data continued ...                :
+ - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
|                     Payload Data continued ...                |
+---------------------------------------------------------------+
```

### Frame Types

| Opcode | Type | Description |
|--------|------|-------------|
| 0x0 | Continuation | Continuation frame |
| 0x1 | Text | UTF-8 text data |
| 0x2 | Binary | Binary data |
| 0x8 | Close | Connection close |
| 0x9 | Ping | Ping frame |
| 0xA | Pong | Pong frame (response to ping) |

## Rate Limiting

Token bucket algorithm per connection:
- **Rate**: Tokens added per second
- **Burst**: Maximum token bucket size
- **Allow**: Check if request should be allowed

```
Connection with rate=10, burst=5:
  t=0:   bucket=5 (initial burst)
  t=0.1: request allowed, bucket=4
  t=0.2: request allowed, bucket=3
  ...
  t=0.5: request allowed, bucket=0
  t=0.6: request denied (bucket empty)
  t=1.1: bucket=1 (1 second elapsed, +1 token)
  t=1.1: request allowed, bucket=0
```

## Payload Scanning

WebSocket text payloads are scanned for threats:

| Pattern | Threat Type |
|---------|-------------|
| `<script`, `javascript:`, `onerror=` | XSS |
| `SELECT`, `INSERT`, `UPDATE`, `DELETE` | SQL Injection |
| `../`, `..\` | Path Traversal |
| `/etc/passwd`, `C:\Windows` | LFI |
| `${jndi:` | Log4j |
| `__proto__`, `constructor` | Prototype Pollution |

## API Endpoints

### GET /api/v1/websocket/stats
Get WebSocket statistics.

**Response:**
```json
{
  "active_connections": 42,
  "total_messages": 15234,
  "total_bytes": 1048576
}
```

### GET /api/v1/websocket/connections
List active connections.

**Response:**
```json
{
  "connections": [
    {
      "id": "conn-abc123",
      "remote_addr": "192.168.1.100",
      "origin": "https://example.com",
      "path": "/ws",
      "connected": "2024-01-15T10:30:00Z",
      "last_seen": "2024-01-15T10:35:00Z",
      "msg_count": 150,
      "byte_count": 45000
    }
  ],
  "count": 1
}
```

## WAF Pipeline Integration

WebSocket security runs at **layer order 76**, right after cluster checks:

```
Order 75: Cluster (IP ban check)
Order 76: WebSocket Security (handshake validation)
Order 100: IP ACL
...
```

## Security Best Practices

### Conservative Configuration
```yaml
websocket:
  enabled: true
  max_message_size: 1048576    # 1MB
  max_frame_size: 65536        # 64KB
  rate_limit_per_second: 50
  max_concurrent_per_ip: 10
  allowed_origins:
    - "https://app.example.com"
  block_empty_messages: true
  block_binary_messages: true
  scan_payloads: true
```

### Production Configuration
```yaml
websocket:
  enabled: true
  max_message_size: 10485760   # 10MB
  max_frame_size: 1048576      # 1MB
  rate_limit_per_second: 100
  max_concurrent_per_ip: 100
  allowed_origins:
    - "https://*.example.com"
  idle_timeout: 300s
```

## Connection Lifecycle

```
1. HTTP Upgrade Request
   → WAF validates handshake
   → Checks origin, limits, extensions

2. WebSocket Established
   → Connection registered
   → Rate limiter initialized

3. Message Exchange
   → Frames parsed and validated
   → Payloads scanned for threats
   → Rate limits enforced
   → Connection stats updated

4. Connection Close
   → Cleanup on close frame
   → Or idle timeout cleanup
```

## Error Handling

| Error | Description | Action |
|-------|-------------|--------|
| Invalid handshake | Missing headers | Block request |
| Origin not allowed | Unauthorized origin | Block request |
| Rate limit exceeded | Too many messages | Drop frame |
| Frame too large | Exceeds max_frame_size | Drop frame |
| Threat detected | Payload contains threat | Block connection |
| Idle timeout | No activity | Close connection |

## Monitoring

Track these metrics:
- Active connections count
- Messages per second
- Bytes transferred
- Rate limit hits
- Threat detections
- Connection duration
- Origin distribution

## Performance

- Frame parsing: ~1μs per frame
- Payload scanning: ~10μs per 1KB
- Rate limit check: ~100ns
- Memory per connection: ~500 bytes
