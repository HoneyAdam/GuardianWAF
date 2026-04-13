# ADR 005: React Dashboard with Go Embed

## Status: Accepted

## Context

GuardianWAF needs a web-based dashboard for real-time security monitoring, configuration management, and analytics. The dashboard must be served from the same binary without external files or services.

## Decision

Build the dashboard using React 19 + TypeScript + Vite 6 + Tailwind CSS 4. The built assets are embedded into the Go binary using `embed.FS` and served by the Go HTTP server. Real-time updates use Server-Sent Events (SSE).

## Consequences

**Positive:**
- Single binary deployment — no separate frontend server needed
- Modern UI with component-based architecture
- Hot-reload development via Vite dev server (proxies API to Go backend)
- Type-safe frontend with TypeScript
- SSE provides real-time updates without WebSocket complexity

**Negative:**
- Build toolchain requires Node.js (development only, not at runtime)
- Increases Go binary size by ~2-4MB (embedded static assets)
- Frontend testing requires separate Vitest setup

## Alternatives Considered

- Server-side rendered templates (Go html/template) — rejected due to limited interactivity
- Vanilla JS — rejected due to poor maintainability at this complexity
- Separate dashboard binary — rejected for deployment simplicity
