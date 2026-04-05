# gRPC Proxy & Reflection

GuardianWAF provides comprehensive gRPC support including HTTP/2 handling, protocol buffer validation, per-method rate limiting, and gRPC reflection for service discovery.

## Features

- **gRPC Proxy**: Full HTTP/2 support for gRPC traffic
- **gRPC-Web Bridge**: Support for browser-based gRPC clients
- **Reflection API**: Service discovery via gRPC reflection
- **Method Rate Limiting**: Per-method token bucket rate limiting
- **Service Filtering**: Allow/block services and methods
- **Streaming Support**: Client, server, and bidirectional streaming
- **Protocol Validation**: Optional protobuf message validation
- **TLS Enforcement**: Require TLS for gRPC connections

## Configuration

```yaml
waf:
  grpc:
    enabled: true
    grpc_web_enabled: true         # Enable gRPC-Web bridge
    reflection_enabled: true       # Enable reflection API
    validate_proto: false          # Validate protobuf messages
    max_message_size: 4194304      # 4MB max message size
    max_stream_duration: 30m       # Max streaming duration
    max_concurrent_streams: 100    # Max streams per connection
    require_tls: false             # Require TLS for gRPC
    
    # Allowed services (empty = allow all)
    allowed_services:
      - "helloworld.Greeter"
      - "myapp.*"                   # Wildcard support
    
    # Blocked services
    blocked_services:
      - "admin.*"
      - "internal.Debug"
    
    # Allowed methods (format: "service/method")
    allowed_methods:
      - "*"                         # Allow all methods
    
    # Blocked methods
    blocked_methods:
      - "admin.Service/DeleteAll"
    
    # Per-method rate limits
    method_rate_limits:
      - method: "helloworld.Greeter/SayHello"
        requests_per_second: 100
        burst_size: 50
      - method: "myapp.Heavy/Process"
        requests_per_second: 10
        burst_size: 5
```

## gRPC Protocol

### HTTP/2 Frame Structure

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                 Length (24)                   |
+-+-+-+-+-------+-+-------------+-------------------------------+
|   Type (8)    |   Flags (8)   |
+-+-+-+-+-------+-+-------------+-------------------------------+
|R|              Stream Identifier (31)                         |
+---------------------------------------------------------------+
|                     Payload (*)                               |
+---------------------------------------------------------------+
```

### Frame Types

| Type | Name | Description |
|------|------|-------------|
| 0x00 | DATA | Application data |
| 0x01 | HEADERS | Header block |
| 0x02 | PRIORITY | Stream priority |
| 0x03 | RST_STREAM | Stream reset |
| 0x04 | SETTINGS | Connection settings |
| 0x05 | PUSH_PROMISE | Server push (not used) |
| 0x06 | PING | Connection heartbeat |
| 0x07 | GOAWAY | Connection termination |
| 0x08 | WINDOW_UPDATE | Flow control |
| 0x09 | CONTINUATION | Header continuation |

### gRPC Status Codes

| Code | Name | Description |
|------|------|-------------|
| 0 | OK | Success |
| 1 | CANCELLED | Operation cancelled |
| 2 | UNKNOWN | Unknown error |
| 3 | INVALID_ARGUMENT | Invalid argument |
| 4 | DEADLINE_EXCEEDED | Deadline exceeded |
| 5 | NOT_FOUND | Entity not found |
| 7 | PERMISSION_DENIED | Permission denied |
| 8 | RESOURCE_EXHAUSTED | Rate limit/quota exceeded |
| 12 | UNIMPLEMENTED | Method not implemented |
| 13 | INTERNAL | Internal error |
| 14 | UNAVAILABLE | Service unavailable |
| 16 | UNAUTHENTICATED | Authentication required |

## gRPC-Web Support

GuardianWAF bridges gRPC-Web to gRPC:

```
Browser (gRPC-Web) → GuardianWAF → Backend (gRPC)

Content-Type mappings:
  application/grpc-web → application/grpc
  application/grpc-web-text → application/grpc
```

### Supported Transports

- **Unary calls**: Full support
- **Server streaming**: Full support
- **Client streaming**: Limited (HTTP/1.1 fallback)
- **Bidirectional streaming**: Limited (HTTP/1.1 fallback)

## Rate Limiting

Token bucket algorithm per method:

```yaml
method_rate_limits:
  - method: "api.Search/Query"
    requests_per_second: 10   # 10 tokens/sec refill
    burst_size: 20            # Max 20 concurrent

Example:
  t=0:   bucket=20 (initial burst)
  t=0.1: request allowed, bucket=19
  ...
  t=1.0: bucket refilled to 20
```

## API Endpoints

### GET /api/v1/grpc/stats
Get gRPC statistics.

**Response:**
```json
{
  "active_streams": 42,
  "total_streams": 15234,
  "total_messages": 1048576,
  "messages_by_method": {
    "helloworld.Greeter/SayHello": 5000,
    "myapp.UserService/GetUser": 3000
  },
  "streams_by_service": {
    "helloworld.Greeter": 15,
    "myapp.UserService": 27
  }
}
```

### GET /api/v1/grpc/streams
List active streams.

**Query Parameters:**
- `service` - Filter by service name

**Response:**
```json
{
  "streams": [
    {
      "id": 1,
      "service": "helloworld.Greeter",
      "method": "SayHello",
      "client_stream": false,
      "server_stream": false,
      "start_time": "2024-01-15T10:30:00Z",
      "duration": "5m30s",
      "last_activity": "2024-01-15T10:35:00Z",
      "messages_sent": 1,
      "messages_recv": 1
    }
  ],
  "count": 1
}
```

### GET /api/v1/grpc/services
List configured services.

**Response:**
```json
{
  "services": [
    {
      "name": "helloworld.Greeter",
      "stream_count": 5,
      "methods": ["SayHello", "SayGoodbye"],
      "allowed": true,
      "blocked": false
    }
  ],
  "count": 1
}
```

## WAF Pipeline Integration

gRPC security runs at **layer order 78**, after WebSocket:

```
Order 76: WebSocket Security
Order 78: gRPC Security
Order 100: IP ACL
...
```

## Security Best Practices

### Production Configuration
```yaml
grpc:
  enabled: true
  grpc_web_enabled: true
  reflection_enabled: false      # Disable in production
  validate_proto: true
  max_message_size: 1048576      # 1MB
  max_stream_duration: 10m
  max_concurrent_streams: 50
  require_tls: true
  allowed_services:
    - "api.v1.*"
  blocked_services:
    - "admin.*"
    - "debug.*"
  method_rate_limits:
    - method: "*/Create*"
      requests_per_second: 10
      burst_size: 5
```

### Development Configuration
```yaml
grpc:
  enabled: true
  grpc_web_enabled: true
  reflection_enabled: true       # Enable for development
  validate_proto: false
  max_message_size: 4194304      # 4MB
  max_stream_duration: 30m
  max_concurrent_streams: 100
  require_tls: false
```

## Connection Lifecycle

```
1. HTTP/2 Connection
   → TLS handshake (if required)
   → HTTP/2 preface validation
   → SETTINGS exchange

2. Request Received
   → Validate content-type
   → Parse method from :path
   → Check service/method allowlist
   → Check rate limits

3. Stream Established
   → Register stream
   → Initialize rate limiter
   → Track message counts

4. Message Exchange
   → Frame validation
   → Message size checks
   → Protocol validation (if enabled)
   → Update activity timestamps

5. Stream Close
   → RST_STREAM or END_STREAM
   → Unregister stream
   → Cleanup resources
```

## Error Handling

| Error | Status Code | Description |
|-------|-------------|-------------|
| Invalid path | 3 (INVALID_ARGUMENT) | Malformed method path |
| Service blocked | 7 (PERMISSION_DENIED) | Service in blocklist |
| Method blocked | 7 (PERMISSION_DENIED) | Method in blocklist |
| Rate limit exceeded | 8 (RESOURCE_EXHAUSTED) | Too many requests |
| Message too large | 3 (INVALID_ARGUMENT) | Exceeds max size |
| TLS required | 16 (UNAUTHENTICATED) | TLS not used |
| Stream timeout | 4 (DEADLINE_EXCEEDED) | Max duration exceeded |

## Monitoring

Track these metrics:
- Active stream count
- Streams per service
- Messages per method
- Rate limit hits
- Protocol errors
- Stream duration
- gRPC-Web vs native ratio

## Performance

- Frame parsing: ~100ns per frame
- Method validation: ~1μs
- Rate limit check: ~100ns
- Memory per stream: ~200 bytes
- Connection overhead: ~1KB

## Reflection API

When `reflection_enabled: true`, GuardianWAF exposes standard gRPC reflection:

```protobuf
service ServerReflection {
  rpc ServerReflectionInfo(stream ServerReflectionRequest)
      returns (stream ServerReflectionResponse);
}
```

Useful for:
- grpc_cli
- gRPC UI tools
- Service discovery
- API documentation
