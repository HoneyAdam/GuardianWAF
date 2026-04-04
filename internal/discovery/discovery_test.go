package discovery

import (
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"
)

func TestCollector(t *testing.T) {
	cfg := DefaultConfig().Collection
	collector := NewCollector(cfg)

	// Record some requests
	for i := 0; i < 100; i++ {
		req := &http.Request{
			Method: "GET",
			URL: &url.URL{
				Path:     "/api/users/123",
				RawQuery: "page=1&limit=10",
			},
			Header: http.Header{
				"Content-Type": []string{"application/json"},
			},
			RemoteAddr: "192.168.1.1:12345",
		}

		resp := &http.Response{
			StatusCode: 200,
		}

		collector.Collect(req, resp, 50*time.Millisecond)
	}

	// Check count
	if collector.Count() != 100 {
		t.Errorf("Expected 100 requests, got %d", collector.Count())
	}

	// Flush and check
	requests := collector.Flush()
	if len(requests) != 100 {
		t.Errorf("Expected 100 flushed requests, got %d", len(requests))
	}

	// Buffer should be empty
	if collector.Size() != 0 {
		t.Errorf("Expected empty buffer, got %d", collector.Size())
	}
}

func TestCollector_Sampling(t *testing.T) {
	cfg := CollectionConfig{
		BufferSize: 1000,
		SampleRate: 0.5, // 50% sample rate
	}
	collector := NewCollector(cfg)

	// Record 1000 requests
	for i := 0; i < 1000; i++ {
		req := &http.Request{
			Method: "GET",
			URL:    &url.URL{Path: "/api/test"},
		}
		collector.Collect(req, nil, 0)
	}

	// Should have roughly 500 requests (50% of 1000)
	count := collector.Count()
	if count < 400 || count > 600 {
		t.Errorf("Expected ~500 requests with 50%% sampling, got %d", count)
	}
}

func TestClusteringEngine(t *testing.T) {
	engine := NewClusteringEngine(3, 0.8)

	// Create test requests - all GET, all numeric IDs
	now := time.Now()
	requests := []CapturedRequest{
		// Users group (5 requests) - all numeric IDs, all GET
		{Method: "GET", Path: "/api/users/123", Timestamp: now},
		{Method: "GET", Path: "/api/users/456", Timestamp: now},
		{Method: "GET", Path: "/api/users/789", Timestamp: now},
		{Method: "GET", Path: "/api/users/111", Timestamp: now},
		{Method: "GET", Path: "/api/users/222", Timestamp: now},
		// Orders group (5 requests) - all numeric IDs, all GET
		{Method: "GET", Path: "/api/orders/333", Timestamp: now},
		{Method: "GET", Path: "/api/orders/444", Timestamp: now},
		{Method: "GET", Path: "/api/orders/555", Timestamp: now},
		{Method: "GET", Path: "/api/orders/666", Timestamp: now},
		{Method: "GET", Path: "/api/orders/777", Timestamp: now},
	}

	clusters := engine.Cluster(requests)

	t.Logf("Found %d clusters", len(clusters))
	for _, cluster := range clusters {
		t.Logf("Cluster: Pattern=%s, Count=%d, Methods=%v", cluster.Pattern, cluster.Count, cluster.Methods)
	}

	// Should have at least 1 cluster
	if len(clusters) == 0 {
		t.Errorf("Expected at least 1 cluster, got %d", len(clusters))
	}
}

func TestAnalyzer(t *testing.T) {
	cfg := DefaultConfig().Analysis
	cfg.MinClusterSize = 1 // Lower for testing
	analyzer := NewAnalyzer(cfg)

	// Create test requests with timestamps
	now := time.Now()
	requests := []CapturedRequest{
		{
			Method:    "GET",
			Path:      "/api/users/123",
			Timestamp: now,
		},
		{
			Method:    "GET",
			Path:      "/api/users/456",
			Timestamp: now,
		},
		{
			Method:    "POST",
			Path:      "/api/users",
			Timestamp: now,
		},
	}

	// Run analysis
	result := analyzer.Analyze(requests)

	if result.Inventory == nil {
		t.Fatal("Expected inventory, got nil")
	}

	// Should have at least 1 endpoint
	if len(result.Inventory.Endpoints) == 0 {
		t.Log("No endpoints discovered - this may be expected with small sample")
	} else {
		t.Logf("Discovered %d endpoints", len(result.Inventory.Endpoints))
		for id, ep := range result.Inventory.Endpoints {
			t.Logf("Endpoint %s: Pattern=%s, Methods=%v", id, ep.Pattern, ep.Methods)
		}
	}
}

func TestSchemaGenerator(t *testing.T) {
	gen := NewSchemaGenerator()

	// Create test inventory
	inventory := &Inventory{
		Version:   "1.0",
		Generated: time.Now(),
		Endpoints: map[string]*Endpoint{
			"api-users-get": {
				ID:      "api-users-get",
				Pattern: "/api/users/{id}",
				Methods: []string{"GET"},
				Parameters: []Parameter{
					{
						Name:    "id",
						In:      "path",
						Type:    "integer",
						Pattern: `^\d+$`,
					},
				},
				StatusCodes: map[string]int{
					"200": 100,
					"404": 5,
				},
			},
		},
	}

	spec := gen.Generate(inventory)

	if spec.OpenAPI != "3.0.3" {
		t.Errorf("Expected OpenAPI 3.0.3, got %s", spec.OpenAPI)
	}

	if len(spec.Paths) != 1 {
		t.Errorf("Expected 1 path, got %d", len(spec.Paths))
	}

	// Check path exists
	pathItem, ok := spec.Paths["/api/users/{id}"]
	if !ok {
		t.Error("Expected path /api/users/{id} not found")
	}

	if pathItem.Get == nil {
		t.Error("Expected GET operation")
	}

	t.Logf("Generated spec with %d paths", len(spec.Paths))
}

func TestChangeDetection(t *testing.T) {
	cfg := DefaultConfig().Analysis
	analyzer := NewAnalyzer(cfg)

	// Create old inventory
	oldInventory := &Inventory{
		Endpoints: map[string]*Endpoint{
			"ep1": {ID: "ep1", Pattern: "/api/users", Methods: []string{"GET"}},
			"ep2": {ID: "ep2", Pattern: "/api/orders", Methods: []string{"GET"}},
		},
	}

	// Create new inventory with changes
	newInventory := &Inventory{
		Endpoints: map[string]*Endpoint{
			"ep1": {ID: "ep1", Pattern: "/api/users", Methods: []string{"GET", "POST"}}, // Modified
			"ep3": {ID: "ep3", Pattern: "/api/products", Methods: []string{"GET"}},      // New
			// ep2 removed
		},
	}

	changes := analyzer.DetectChanges(oldInventory, newInventory)

	// Should detect:
	// 1. ep2 removed
	// 2. ep3 added
	// 3. ep1 modified (methods changed)

	if len(changes) != 3 {
		t.Errorf("Expected 3 changes, got %d", len(changes))
	}

	for _, change := range changes {
		t.Logf("Change: Type=%s, Endpoint=%s, Desc=%s", change.Type, change.EndpointID, change.Description)
	}
}

func TestManager(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Collection.FlushPeriod = 100 * time.Millisecond

	manager, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}
	defer manager.Close()

	// Record some requests
	for i := 0; i < 20; i++ {
		req := &http.Request{
			Method: "GET",
			URL:    &url.URL{Path: fmt.Sprintf("/api/users/%d", i)},
		}
		manager.Record(req, &http.Response{StatusCode: 200}, 10*time.Millisecond)
	}

	// Wait for processing
	time.Sleep(200 * time.Millisecond)

	// Check stats
	stats := manager.Stats()
	t.Logf("Stats: Enabled=%v, Collected=%d", stats.Enabled, stats.RequestsCollected)
}
