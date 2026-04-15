package discovery

import (
	"net/http"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Layer wraps the discovery Engine as an engine.Layer for pipeline integration.
// It runs at Order 310 — after Sanitizer, before CRS — to capture normalized requests.
// The layer is entirely passive: it records requests for later OpenAPI export but
// does not block or alter request processing.
type Layer struct {
	engine *Engine
	order  int
}

// NewLayer creates a new discovery layer.
func NewLayer(cfg *EngineConfig) (*Layer, error) {
	if cfg == nil {
		ec := EngineConfig{
			CaptureMode:       "passive",
			RingBufferSize:   10000,
			MinSamples:       10,
			ClusterThreshold: 0.8,
			ExportPath:       "data/api-discovery",
			ExportFormat:    "openapi",
			AutoExport:      true,
			ExportInterval:  5 * time.Minute,
		}
		cfg = &ec
	}

	eng, err := NewEngine(cfg)
	if err != nil {
		return nil, err
	}

	return &Layer{
		engine: eng,
		order:  310,
	}, nil
}

// Name returns the layer name.
func (l *Layer) Name() string {
	return "api-discovery"
}

// Order returns the layer execution order.
func (l *Layer) Order() int {
	return 310
}

// Process records the request for passive API discovery.
// It always returns ActionPass — discovery does not block requests.
func (l *Layer) Process(ctx *engine.RequestContext) engine.LayerResult {
	result := engine.LayerResult{
		Action:   engine.ActionPass,
		Duration: 0,
	}

	if l.engine == nil || l.engine.manager == nil {
		return result
	}

	// Record the request (passive — no decisions made)
	if ctx.Request != nil {
		// Status code may be set in metadata by response layer after request processing
		statusCode := 0
		if sc, ok := ctx.Metadata["status_code"].(int); ok {
			statusCode = sc
		}
		l.engine.RecordRequest(ctx.Request, statusCode)
	}

	return result
}

// RecordRequest records a request/response pair directly.
func (l *Layer) RecordRequest(r *http.Request, statusCode int) {
	if l.engine != nil {
		l.engine.RecordRequest(r, statusCode)
	}
}

// ExportToOpenAPI exports the discovered API as OpenAPI spec.
func (l *Layer) ExportToOpenAPI() *OpenAPISpec {
	if l.engine == nil {
		return nil
	}
	return l.engine.ExportToOpenAPI()
}

// GetStats returns discovery statistics.
func (l *Layer) GetStats() DiscoveryStats {
	if l.engine == nil || l.engine.manager == nil {
		return DiscoveryStats{}
	}
	return l.engine.GetStats()
}

// Start starts the discovery background processing.
func (l *Layer) Start() {
	// Manager runs its background goroutine on creation
}

// Stop stops the discovery engine.
func (l *Layer) Stop() {
	if l.engine != nil {
		l.engine.Stop()
	}
}

// Ensure Layer implements engine.Layer
var _ engine.Layer = (*Layer)(nil)
