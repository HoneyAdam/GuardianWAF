// Package discovery provides automatic API endpoint discovery from HTTP traffic.
package discovery

import (
	"context"
	"net/http"
	"sync"
	"time"
)

// Manager coordinates API discovery components.
type Manager struct {
	mu sync.RWMutex

	enabled bool
	config  Config

	collector *Collector
	analyzer  *Analyzer
	storage   Storage

	// Background processing
	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}
}

// Config for API discovery.
type Config struct {
	Enabled bool `json:"enabled" yaml:"enabled"`

	Collection CollectionConfig `json:"collection" yaml:"collection"`
	Analysis   AnalysisConfig   `json:"analysis" yaml:"analysis"`
	Storage    StorageConfig    `json:"storage" yaml:"storage"`
}

// CollectionConfig for traffic collection.
type CollectionConfig struct {
	BufferSize     int           `json:"buffer_size" yaml:"buffer_size"`
	SampleRate     float64       `json:"sample_rate" yaml:"sample_rate"`
	BodySampleSize int           `json:"body_sample_size" yaml:"body_sample_size"`
	FlushPeriod    time.Duration `json:"flush_period" yaml:"flush_period"`
}

// AnalysisConfig for traffic analysis.
type AnalysisConfig struct {
	MinClusterSize      int           `json:"min_cluster_size" yaml:"min_cluster_size"`
	SimilarityThreshold float64       `json:"similarity_threshold" yaml:"similarity_threshold"`
	LearningPeriod      time.Duration `json:"learning_period" yaml:"learning_period"`
	AutoLearning        bool          `json:"auto_learning" yaml:"auto_learning"`
}

// StorageConfig for persistence.
type StorageConfig struct {
	Path      string        `json:"path" yaml:"path"`
	Retention time.Duration `json:"retention" yaml:"retention"`
}

// DefaultConfig returns default discovery configuration.
func DefaultConfig() Config {
	return Config{
		Enabled: true,
		Collection: CollectionConfig{
			BufferSize:     10000,
			SampleRate:     1.0,
			BodySampleSize: 1024,
			FlushPeriod:    5 * time.Minute,
		},
		Analysis: AnalysisConfig{
			MinClusterSize:      10,
			SimilarityThreshold: 0.8,
			LearningPeriod:      24 * time.Hour,
			AutoLearning:        true,
		},
		Storage: StorageConfig{
			Path:      "/var/lib/guardianwaf/api",
			Retention: 30 * 24 * time.Hour,
		},
	}
}

// NewManager creates a new discovery manager.
func NewManager(cfg Config) (*Manager, error) {
	ctx, cancel := context.WithCancel(context.Background())

	m := &Manager{
		enabled: cfg.Enabled,
		config:  cfg,
		ctx:     ctx,
		cancel:  cancel,
		done:    make(chan struct{}),
	}

	// Initialize collector
	m.collector = NewCollector(cfg.Collection)

	// Initialize analyzer
	m.analyzer = NewAnalyzer(cfg.Analysis)

	// Initialize storage (in-memory for POC)
	m.storage = NewMemoryStorage()

	// Start background processing
	if cfg.Enabled {
		go m.run()
	}

	return m, nil
}

// Record records an HTTP request for discovery.
func (m *Manager) Record(req *http.Request, resp *http.Response, latency time.Duration) {
	if !m.Enabled() {
		return
	}

	m.collector.Collect(req, resp, latency)
}

// Enabled returns whether discovery is enabled.
func (m *Manager) Enabled() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.enabled
}

// SetEnabled enables or disables discovery.
func (m *Manager) SetEnabled(enabled bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.enabled == enabled {
		return
	}

	m.enabled = enabled
	if enabled {
		// Create fresh context since the old one may have been canceled
		ctx, cancel := context.WithCancel(context.Background())
		m.ctx = ctx
		m.cancel = cancel
		go m.run()
	} else {
		m.cancel()
	}
}

// Inventory returns the current API inventory.
func (m *Manager) Inventory() *Inventory {
	return m.storage.GetInventory()
}

// GetEndpoint returns a specific endpoint by ID.
func (m *Manager) GetEndpoint(id string) *Endpoint {
	return m.storage.GetEndpoint(id)
}

// GetChanges returns recent changes.
func (m *Manager) GetChanges(since time.Time) []Change {
	return m.storage.GetChanges(since)
}

// ExportOpenAPI generates OpenAPI spec from current inventory.
func (m *Manager) ExportOpenAPI() *OpenAPISpec {
	inventory := m.Inventory()
	if inventory == nil {
		return nil
	}

	gen := NewSchemaGenerator()
	return gen.Generate(inventory)
}

// Stats returns discovery statistics.
func (m *Manager) Stats() Stats {
	return Stats{
		Enabled:           m.Enabled(),
		RequestsCollected: m.collector.Count(),
		EndpointsDiscovered: len(m.Inventory().Endpoints),
		LastAnalysis:      m.analyzer.LastRun(),
	}
}

// Stats contains discovery statistics.
type Stats struct {
	Enabled             bool
	RequestsCollected   int64
	EndpointsDiscovered int
	LastAnalysis        time.Time
}

// run is the background processing loop.
func (m *Manager) run() {
	ticker := time.NewTicker(m.config.Collection.FlushPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			close(m.done)
			return
		case <-ticker.C:
			m.process()
		}
	}
}

// process analyzes collected traffic.
func (m *Manager) process() {
	// Get requests from collector
	requests := m.collector.Flush()
	if len(requests) == 0 {
		return
	}

	// Run analysis
	result := m.analyzer.Analyze(requests)

	// Update inventory
	m.storage.UpdateInventory(result.Inventory)

	// Detect and store changes
	changes := m.analyzer.DetectChanges(m.storage.GetInventory(), result.Inventory)
	for _, change := range changes {
		m.storage.AddChange(change)
	}
}

// Close shuts down the discovery manager.
func (m *Manager) Close() error {
	m.cancel()
	<-m.done
	return nil
}
