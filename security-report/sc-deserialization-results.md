# Insecure Deserialization Scanner Results

**Scanner:** sc-deserialization
**Language:** Go
**Target:** D:/CODEBOX/PROJECTS/GuardianWAF

## Summary

| Category | Count |
|----------|-------|
| Critical | 0 |
| High | 0 |
| Medium | 0 |
| Low | 0 |

## Findings

No deserialization vulnerabilities detected.

## Analysis Details

### encoding/gob Usage
- **File:** `docs/adr/0023-high-availability-raft.md:97`
- **Context:** State machine snapshotting (internal disk persistence, not network-facing)
- **Risk:** None - snapshots are stored locally, not received from untrusted sources

### JSON Unmarshaling
- **Files:** Multiple (cmd/guardianwaf/main.go, internal/ai/analyzer.go, internal/layers/apivalidation/yaml.go, etc.)
- **Risk:** None - standard JSON parsing does not support arbitrary object instantiation (safe format)

### YAML Unmarshaling
- **File:** `internal/layers/apivalidation/yaml.go:267` - `SimpleYAMLUnmarshal`
- **Pattern:** Converts YAML to JSON first via `YAMLToJSON`, then uses `json.Unmarshal`
- **Risk:** None - YAML is converted to JSON, no unsafe deserialization

### Binary Protocols
- **Files:** `internal/layers/websocket/websocket.go`, `internal/layers/grpc/grpc.go`, `internal/proxy/grpc/proxy.go`
- **Pattern:** `binary.Read` / `binary.Write` on fixed-size protocol frames
- **Risk:** None - binary.Read writes into fixed-size native types (uint16, uint64), no arbitrary object instantiation

### Dangerous Patterns Searched
| Pattern | Found |
|---------|-------|
| gob.NewDecoder / gob.Decode | No |
| pickle.loads / Marshal.load | No |
| ObjectInputStream / readObject | No |
| PHP unserialize | No |
| BinaryFormatter | No |
| yaml.load with unsafe tags (!<!>) | No |
| unsafe pointer operations | No |

## Conclusion

The GuardianWAF codebase uses only safe deserialization formats:
- **JSON** - safe, no code execution capability
- **Protocol Buffers** (via gRPC) - schema-defined, safe
- **encoding/binary** - fixed-size native types only, safe
- **YAML** - converted to JSON before unmarshal, safe

No insecure deserialization vulnerabilities were identified.
