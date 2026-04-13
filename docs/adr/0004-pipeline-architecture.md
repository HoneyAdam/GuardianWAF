# ADR 004: Pipeline Architecture

## Status: Accepted

## Context

WAF processing involves multiple independent checks (IP filtering, rate limiting, detection, bot detection, etc.) that must execute in a defined order with short-circuit capability. Some layers depend on the results of previous layers.

## Decision

Implement a layer pipeline where each layer implements a `Layer` interface with `Name()` and `Process(ctx *RequestContext) LayerResult`. Layers are sorted by an `Order` constant and executed sequentially. The pipeline short-circuits on `ActionBlock` — no further layers run once a block decision is made.

## Consequences

**Positive:**
- Easy to add new layers (implement interface, set order constant)
- Clear execution order via numeric constants
- Short-circuit prevents wasted CPU on blocked requests
- Per-request context (`RequestContext`) carries all state through the pipeline
- Layers are independently testable

**Negative:**
- Layers must be stateless or carefully manage concurrent access
- Order constants must be manually managed to avoid collisions
- No parallel layer execution (sequential by design)

## Alternatives Considered

- Middleware chain — less explicit ordering, harder to short-circuit
- Event-driven layers — more complex, harder to reason about execution order
