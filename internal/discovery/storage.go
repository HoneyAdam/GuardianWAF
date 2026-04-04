package discovery

import (
	"sync"
	"time"
)

// Storage interface for persisting discovery data.
type Storage interface {
	GetInventory() *Inventory
	UpdateInventory(inventory *Inventory)
	GetEndpoint(id string) *Endpoint
	GetChanges(since time.Time) []Change
	AddChange(change Change)
}

// MemoryStorage implements in-memory storage (for POC).
type MemoryStorage struct {
	mu sync.RWMutex

	inventory *Inventory
	changes   []Change
}

// NewMemoryStorage creates a new in-memory storage.
func NewMemoryStorage() *MemoryStorage {
	return &MemoryStorage{
		inventory: &Inventory{
			Version:   "1.0",
			Endpoints: make(map[string]*Endpoint),
			Generated: time.Now(),
		},
		changes: make([]Change, 0),
	}
}

// GetInventory returns the current inventory.
func (s *MemoryStorage) GetInventory() *Inventory {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Return a copy
	return s.inventory.Clone()
}

// UpdateInventory updates the API inventory.
func (s *MemoryStorage) UpdateInventory(inventory *Inventory) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.inventory = inventory
}

// GetEndpoint returns a specific endpoint.
func (s *MemoryStorage) GetEndpoint(id string) *Endpoint {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if ep, ok := s.inventory.Endpoints[id]; ok {
		return ep
	}
	return nil
}

// GetChanges returns changes since a given time.
func (s *MemoryStorage) GetChanges(since time.Time) []Change {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []Change
	for _, change := range s.changes {
		if change.Timestamp.After(since) {
			result = append(result, change)
		}
	}
	return result
}

// AddChange adds a new change.
func (s *MemoryStorage) AddChange(change Change) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.changes = append(s.changes, change)

	// Keep only last 1000 changes
	if len(s.changes) > 1000 {
		s.changes = s.changes[len(s.changes)-1000:]
	}
}

// Inventory represents the discovered API inventory.
type Inventory struct {
	Version      string               `json:"version"`
	Generated    time.Time            `json:"generated_at"`
	Endpoints    map[string]*Endpoint `json:"endpoints"`
	Statistics   Statistics           `json:"statistics"`
	LastAnalysis time.Time            `json:"last_analysis"`
}

// Clone creates a deep copy of the inventory.
func (i *Inventory) Clone() *Inventory {
	clone := &Inventory{
		Version:      i.Version,
		Generated:    i.Generated,
		Endpoints:    make(map[string]*Endpoint),
		Statistics:   i.Statistics,
		LastAnalysis: i.LastAnalysis,
	}

	for k, v := range i.Endpoints {
		clone.Endpoints[k] = v.Clone()
	}

	return clone
}

// Endpoint represents a discovered API endpoint.
type Endpoint struct {
	ID            string         `json:"id"`
	Pattern       string         `json:"pattern"`        // /api/users/{id}
	PathRegex     string         `json:"path_regex"`     // ^/api/users/[^/]+$
	Methods       []string       `json:"methods"`
	Parameters    []Parameter    `json:"parameters"`
	Examples      []string       `json:"examples"`
	Count         int            `json:"count"`
	FirstSeen     time.Time      `json:"first_seen"`
	LastSeen      time.Time      `json:"last_seen"`
	StatusCodes   map[string]int `json:"status_codes"`   // "200": 150, "404": 10
	AvgLatency    float64        `json:"avg_latency_ms"`
	Tags          []string       `json:"tags"`           // "sensitive", "auth-required"
}

// Clone creates a deep copy of the endpoint.
func (e *Endpoint) Clone() *Endpoint {
	clone := &Endpoint{
		ID:          e.ID,
		Pattern:     e.Pattern,
		PathRegex:   e.PathRegex,
		Methods:     make([]string, len(e.Methods)),
		Parameters:  make([]Parameter, len(e.Parameters)),
		Examples:    make([]string, len(e.Examples)),
		Count:       e.Count,
		FirstSeen:   e.FirstSeen,
		LastSeen:    e.LastSeen,
		StatusCodes: make(map[string]int),
		AvgLatency:  e.AvgLatency,
		Tags:        make([]string, len(e.Tags)),
	}

	copy(clone.Methods, e.Methods)
	copy(clone.Parameters, e.Parameters)
	copy(clone.Examples, e.Examples)

	for k, v := range e.StatusCodes {
		clone.StatusCodes[k] = v
	}

	copy(clone.Tags, e.Tags)

	return clone
}

// Statistics contains API discovery statistics.
type Statistics struct {
	TotalEndpoints    int     `json:"total_endpoints"`
	TotalRequests     int64   `json:"total_requests"`
	CoveragePercent   float64 `json:"coverage_percent"`
	UniquePaths       int     `json:"unique_paths"`
	DynamicEndpoints  int     `json:"dynamic_endpoints"`
}

// Change represents an API change.
type Change struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"`        // "new", "removed", "modified"
	Severity    string    `json:"severity"`    // "low", "medium", "high"
	EndpointID  string    `json:"endpoint_id"`
	Pattern     string    `json:"pattern"`
	Description string    `json:"description"`
	Timestamp   time.Time `json:"timestamp"`
}

// ChangeType constants.
const (
	ChangeTypeNew      = "new"
	ChangeTypeRemoved  = "removed"
	ChangeTypeModified = "modified"
)

// Severity constants.
const (
	SeverityLow    = "low"
	SeverityMedium = "medium"
	SeverityHigh   = "high"
)
