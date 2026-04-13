# ADR 006: Multi-Tenant Isolation via Request Context

## Status: Accepted

## Context

GuardianWAF supports multi-tenant deployments where different domains are protected by different WAF configurations. Tenant isolation must be race-free and performant under high concurrency.

## Decision

Tenant WAF configuration is loaded per-request into `RequestContext.TenantWAFConfig`. Each layer reads this field directly rather than accessing shared state. Tenant resolution happens once at request entry via the `Host` header → domain mapping.

## Consequences

**Positive:**
- No shared mutable state between tenants — race-free by design
- Per-request config allows safe hot-reload without locks
- Layers don't need to know about tenants — they read config from context
- Zero-overhead for single-tenant deployments (nil TenantWAFConfig)

**Negative:**
- Memory usage scales with concurrent requests × tenants
- Tenant lookup on every request (mitigated by domain map cache)
- Config changes are eventually consistent (reads in-flight use old config)

## Alternatives Considered

- Per-tenant pipeline instances — rejected due to memory overhead and sync complexity
- Global config with tenant-specific overrides in shared map — rejected due to race conditions
