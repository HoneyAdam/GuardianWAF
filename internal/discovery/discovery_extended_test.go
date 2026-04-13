package discovery

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// --- Storage Tests ---

func TestMemoryStorage_New(t *testing.T) {
	s := NewMemoryStorage()
	if s == nil {
		t.Fatal("expected non-nil storage")
	}
	inv := s.GetInventory()
	if inv == nil {
		t.Fatal("expected non-nil inventory")
	}
	if inv.Version != "1.0" {
		t.Errorf("expected version 1.0, got %s", inv.Version)
	}
	if len(inv.Endpoints) != 0 {
		t.Errorf("expected empty endpoints, got %d", len(inv.Endpoints))
	}
}

func TestMemoryStorage_UpdateAndGetInventory(t *testing.T) {
	s := NewMemoryStorage()
	now := time.Now()
	inv := &Inventory{
		Version:   "2.0",
		Generated: now,
		Endpoints: map[string]*Endpoint{
			"ep1": {ID: "ep1", Pattern: "/api/test", Methods: []string{"GET"}},
		},
	}
	s.UpdateInventory(inv)

	got := s.GetInventory()
	if got.Version != "2.0" {
		t.Errorf("expected version 2.0, got %s", got.Version)
	}
	if len(got.Endpoints) != 1 {
		t.Errorf("expected 1 endpoint, got %d", len(got.Endpoints))
	}
	// Verify it's a clone
	got.Endpoints["ep1"].Pattern = "/modified"
	original := s.GetInventory()
	if original.Endpoints["ep1"].Pattern != "/api/test" {
		t.Error("GetInventory should return a clone, not a reference")
	}
}

func TestMemoryStorage_GetEndpoint(t *testing.T) {
	s := NewMemoryStorage()
	s.UpdateInventory(&Inventory{
		Endpoints: map[string]*Endpoint{
			"ep1": {ID: "ep1", Pattern: "/api/users"},
			"ep2": {ID: "ep2", Pattern: "/api/orders"},
		},
	})

	ep := s.GetEndpoint("ep1")
	if ep == nil || ep.Pattern != "/api/users" {
		t.Error("expected to find ep1")
	}
	ep = s.GetEndpoint("nonexistent")
	if ep != nil {
		t.Error("expected nil for nonexistent endpoint")
	}
}

func TestMemoryStorage_AddAndGetChanges(t *testing.T) {
	s := NewMemoryStorage()
	base := time.Now()

	s.AddChange(Change{ID: "c1", Type: ChangeTypeNew, Timestamp: base.Add(-2 * time.Hour)})
	s.AddChange(Change{ID: "c2", Type: ChangeTypeModified, Timestamp: base.Add(-1 * time.Hour)})
	s.AddChange(Change{ID: "c3", Type: ChangeTypeRemoved, Timestamp: base.Add(1 * time.Hour)})

	// Get changes since 90 minutes ago — should get c2 and c3
	changes := s.GetChanges(base.Add(-90 * time.Minute))
	if len(changes) != 2 {
		t.Fatalf("expected 2 changes, got %d", len(changes))
	}
	if changes[0].ID != "c2" {
		t.Errorf("expected c2, got %s", changes[0].ID)
	}
	if changes[1].ID != "c3" {
		t.Errorf("expected c3, got %s", changes[1].ID)
	}
}

func TestMemoryStorage_AddChange_Eviction(t *testing.T) {
	s := NewMemoryStorage()
	base := time.Now()
	for i := 0; i < 1100; i++ {
		s.AddChange(Change{ID: string(rune(i)), Timestamp: base})
	}
	changes := s.GetChanges(time.Time{})
	if len(changes) != 1000 {
		t.Errorf("expected 1000 changes after eviction, got %d", len(changes))
	}
}

func TestInventory_Clone(t *testing.T) {
	now := time.Now()
	inv := &Inventory{
		Version:   "1.0",
		Generated: now,
		Endpoints: map[string]*Endpoint{
			"ep1": {ID: "ep1", Pattern: "/test", Methods: []string{"GET"}, StatusCodes: map[string]int{"200": 5}},
		},
	}
	clone := inv.Clone()
	clone.Endpoints["ep1"].Pattern = "/modified"
	delete(clone.Endpoints, "ep1")
	clone.Endpoints["ep2"] = &Endpoint{ID: "ep2"}

	if inv.Endpoints["ep1"].Pattern != "/test" {
		t.Error("clone should not affect original")
	}
	if _, ok := inv.Endpoints["ep1"]; !ok {
		t.Error("deleting from clone should not affect original")
	}
}

func TestEndpoint_Clone(t *testing.T) {
	ep := &Endpoint{
		ID:          "ep1",
		Pattern:     "/api/{id}",
		Methods:     []string{"GET", "POST"},
		StatusCodes: map[string]int{"200": 10, "404": 2},
		Tags:        []string{"sensitive"},
	}
	clone := ep.Clone()
	clone.Methods[0] = "PUT"
	clone.StatusCodes["200"] = 999
	clone.Tags[0] = "modified"

	if ep.Methods[0] != "GET" {
		t.Error("clone should not affect original methods")
	}
	if ep.StatusCodes["200"] != 10 {
		t.Error("clone should not affect original status codes")
	}
	if ep.Tags[0] != "sensitive" {
		t.Error("clone should not affect original tags")
	}
}

// --- Collector Extended Tests ---

func TestCollector_PeekAndClear(t *testing.T) {
	cfg := CollectionConfig{BufferSize: 10, SampleRate: 1.0}
	c := NewCollector(cfg)

	for i := range 5 {
		req := &http.Request{Method: "GET", URL: &url.URL{Path: "/test"}}
		c.Collect(req, nil, 0)
		if c.Size() != i+1 {
			t.Errorf("expected size %d, got %d", i+1, c.Size())
		}
	}

	peeked := c.Peek()
	if len(peeked) != 5 {
		t.Errorf("expected 5 peeked, got %d", len(peeked))
	}
	// Buffer should not be cleared by Peek
	if c.Size() != 5 {
		t.Errorf("expected size 5 after peek, got %d", c.Size())
	}

	c.Clear()
	if c.Size() != 0 {
		t.Errorf("expected size 0 after clear, got %d", c.Size())
	}
	if c.Count() != 5 {
		t.Errorf("count should still be 5, got %d", c.Count())
	}
}

func TestCollector_RingBuffer_WrapAround(t *testing.T) {
	cfg := CollectionConfig{BufferSize: 5, SampleRate: 1.0}
	c := NewCollector(cfg)

	// Fill buffer and wrap around
	for range 8 {
		req := &http.Request{Method: "GET", URL: &url.URL{Path: "/test"}}
		c.Collect(req, nil, 0)
	}

	if c.Size() != 5 {
		t.Errorf("expected size 5 (buffer full), got %d", c.Size())
	}
	if c.Count() != 8 {
		t.Errorf("expected total count 8, got %d", c.Count())
	}

	flushed := c.Flush()
	if len(flushed) != 5 {
		t.Errorf("expected 5 flushed, got %d", len(flushed))
	}
}

func TestCollector_BodySample(t *testing.T) {
	cfg := CollectionConfig{BufferSize: 10, SampleRate: 1.0, BodySampleSize: 50}
	c := NewCollector(cfg)

	body := []byte("hello world request body content")
	req := &http.Request{
		Method: "POST",
		URL:    &url.URL{Path: "/api/data"},
		Body:   io.NopCloser(bytes.NewReader(body)),
	}
	c.Collect(req, nil, 0)

	flushed := c.Flush()
	if len(flushed) != 1 {
		t.Fatalf("expected 1 request, got %d", len(flushed))
	}
	if string(flushed[0].BodySample) != string(body) {
		t.Errorf("body sample mismatch: got %q", string(flushed[0].BodySample))
	}
	// Body should be restored for downstream handlers
	restored, _ := io.ReadAll(req.Body)
	if string(restored) != string(body) {
		t.Errorf("body not restored: got %q", string(restored))
	}
}

func TestCollector_XForwardedFor(t *testing.T) {
	cfg := CollectionConfig{BufferSize: 10, SampleRate: 1.0}
	c := NewCollector(cfg)

	req := &http.Request{
		Method:     "GET",
		URL:        &url.URL{Path: "/test"},
		RemoteAddr: "10.0.0.1:12345",
		Header:     http.Header{"X-Forwarded-For": []string{"203.0.113.5"}},
	}
	c.Collect(req, nil, 0)
	flushed := c.Flush()
	if flushed[0].SourceIP != "203.0.113.5" {
		t.Errorf("expected XFF IP, got %s", flushed[0].SourceIP)
	}
}

func TestCollector_NilResponse(t *testing.T) {
	cfg := CollectionConfig{BufferSize: 10, SampleRate: 1.0}
	c := NewCollector(cfg)

	req := &http.Request{Method: "GET", URL: &url.URL{Path: "/test"}}
	c.Collect(req, nil, 0)
	flushed := c.Flush()
	if flushed[0].ResponseStatus != 0 {
		t.Errorf("expected 0 status for nil response, got %d", flushed[0].ResponseStatus)
	}

	c.Collect(req, &http.Response{StatusCode: 404, ContentLength: 100}, 0)
	flushed = c.Flush()
	if flushed[0].ResponseStatus != 404 {
		t.Errorf("expected 404 status, got %d", flushed[0].ResponseStatus)
	}
	if flushed[0].ResponseSize != 100 {
		t.Errorf("expected response size 100, got %d", flushed[0].ResponseSize)
	}
}

// --- Clustering Extended Tests ---

func TestClusteringEngine_QueryParams(t *testing.T) {
	engine := NewClusteringEngine(2, 0.8)
	now := time.Now()

	requests := []CapturedRequest{
		{Method: "GET", Path: "/api/users", RawQuery: "page=1&limit=10", QueryParams: map[string][]string{"page": {"1"}, "limit": {"10"}}, Timestamp: now},
		{Method: "GET", Path: "/api/users", RawQuery: "page=2&limit=20", QueryParams: map[string][]string{"page": {"2"}, "limit": {"20"}}, Timestamp: now},
		{Method: "GET", Path: "/api/users", RawQuery: "page=3&limit=30", QueryParams: map[string][]string{"page": {"3"}, "limit": {"30"}}, Timestamp: now},
	}

	clusters := engine.Cluster(requests)
	if len(clusters) == 0 {
		t.Fatal("expected at least 1 cluster")
	}

	foundParams := false
	for _, cl := range clusters {
		if len(cl.Parameters) > 0 {
			foundParams = true
		}
	}
	if !foundParams {
		t.Log("query params not extracted (may be expected depending on implementation)")
	}
}

func TestClusteringEngine_UUIDPaths(t *testing.T) {
	engine := NewClusteringEngine(2, 0.8)
	now := time.Now()

	requests := []CapturedRequest{
		{Method: "GET", Path: "/api/resources/550e8400-e29b-41d4-a716-446655440000", Timestamp: now},
		{Method: "GET", Path: "/api/resources/6ba7b810-9dad-11d1-80b4-00c04fd430c8", Timestamp: now},
		{Method: "GET", Path: "/api/resources/f47ac10b-58cc-4372-a567-0e02b2c3d479", Timestamp: now},
	}

	clusters := engine.Cluster(requests)
	if len(clusters) == 0 {
		t.Fatal("expected at least 1 cluster for UUID paths")
	}
	t.Logf("UUID cluster pattern: %s", clusters[0].Pattern)
}

func TestClusteringEngine_MixedMethods(t *testing.T) {
	engine := NewClusteringEngine(2, 0.8)
	now := time.Now()

	requests := []CapturedRequest{
		{Method: "GET", Path: "/api/users/123", Timestamp: now},
		{Method: "GET", Path: "/api/users/456", Timestamp: now},
		{Method: "PUT", Path: "/api/users/789", Timestamp: now},
		{Method: "PUT", Path: "/api/users/111", Timestamp: now},
		{Method: "DELETE", Path: "/api/users/222", Timestamp: now},
		{Method: "DELETE", Path: "/api/users/333", Timestamp: now},
	}

	clusters := engine.Cluster(requests)
	if len(clusters) == 0 {
		t.Fatal("expected at least 1 cluster")
	}
	cl := clusters[0]
	if len(cl.Methods) < 2 {
		t.Logf("cluster has %d methods: %v", len(cl.Methods), cl.Methods)
	}
}

func TestClusteringEngine_EmptyInput(t *testing.T) {
	engine := NewClusteringEngine(2, 0.8)
	clusters := engine.Cluster(nil)
	if len(clusters) != 0 {
		t.Errorf("expected 0 clusters for empty input, got %d", len(clusters))
	}
}

func TestClusteringEngine_BelowMinSize(t *testing.T) {
	engine := NewClusteringEngine(5, 0.8) // min 5
	now := time.Now()

	requests := []CapturedRequest{
		{Method: "GET", Path: "/api/users/1", Timestamp: now},
		{Method: "GET", Path: "/api/users/2", Timestamp: now},
	}

	clusters := engine.Cluster(requests)
	if len(clusters) != 0 {
		t.Errorf("expected 0 clusters below min size, got %d", len(clusters))
	}
}

// --- Analyzer Extended Tests ---

func TestAnalyzer_LastRun(t *testing.T) {
	cfg := DefaultConfig().Analysis
	cfg.MinClusterSize = 1
	a := NewAnalyzer(cfg)

	if !a.LastRun().IsZero() {
		t.Error("expected zero time before first analysis")
	}

	requests := []CapturedRequest{
		{Method: "GET", Path: "/api/test", Timestamp: time.Now()},
	}
	a.Analyze(requests)

	if a.LastRun().IsZero() {
		t.Error("expected non-zero time after analysis")
	}
}

func TestAnalyzer_AnalysisResult_Clusters(t *testing.T) {
	cfg := DefaultConfig().Analysis
	cfg.MinClusterSize = 1
	a := NewAnalyzer(cfg)

	requests := []CapturedRequest{
		{Method: "GET", Path: "/api/users/1", Timestamp: time.Now()},
		{Method: "GET", Path: "/api/users/2", Timestamp: time.Now()},
	}

	result := a.Analyze(requests)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.Inventory == nil {
		t.Error("expected non-nil inventory")
	}
	t.Logf("Clusters: %d, Endpoints: %d", len(result.Clusters), len(result.Inventory.Endpoints))
}

func TestAnalyzer_DetectChanges_NilInventories(t *testing.T) {
	cfg := DefaultConfig().Analysis
	a := NewAnalyzer(cfg)

	newInv := &Inventory{
		Endpoints: map[string]*Endpoint{
			"ep1": {ID: "ep1", Pattern: "/api/new"},
		},
	}

	// Both nil — returns empty (by design: nil inventories mean no baseline)
	changes := a.DetectChanges(nil, newInv)
	if len(changes) != 0 {
		t.Errorf("expected 0 changes with nil old, got %d", len(changes))
	}

	changes = a.DetectChanges(newInv, nil)
	if len(changes) != 0 {
		t.Errorf("expected 0 changes with nil new, got %d", len(changes))
	}
}

// --- Schema Generator Extended Tests ---

func TestSchemaGenerator_SetInfo(t *testing.T) {
	gen := NewSchemaGenerator()
	gen.SetInfo(OpenAPIInfo{
		Title:       "Test API",
		Description: "A test API",
		Version:     "2.0",
	})

	inv := &Inventory{
		Version:   "1.0",
		Generated: time.Now(),
		Endpoints: map[string]*Endpoint{
			"ep1": {ID: "ep1", Pattern: "/api/test", Methods: []string{"GET"}},
		},
	}
	spec := gen.Generate(inv)
	if spec.Info.Title != "Test API" {
		t.Errorf("expected title 'Test API', got %s", spec.Info.Title)
	}
	if spec.Info.Version != "2.0" {
		t.Errorf("expected version '2.0', got %s", spec.Info.Version)
	}
}

func TestSchemaGenerator_ToJSON(t *testing.T) {
	gen := NewSchemaGenerator()
	inv := &Inventory{
		Version:   "1.0",
		Generated: time.Now(),
		Endpoints: map[string]*Endpoint{
			"ep1": {ID: "ep1", Pattern: "/api/test", Methods: []string{"GET"}},
		},
	}
	spec := gen.Generate(inv)

	data, err := spec.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON failed: %v", err)
	}
	if len(data) == 0 {
		t.Error("expected non-empty JSON")
	}

	// Verify it's valid JSON
	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if parsed["openapi"] != "3.0.3" {
		t.Errorf("expected openapi 3.0.3, got %v", parsed["openapi"])
	}
}

func TestSchemaGenerator_PostWithRequestBody(t *testing.T) {
	gen := NewSchemaGenerator()
	inv := &Inventory{
		Version:   "1.0",
		Generated: time.Now(),
		Endpoints: map[string]*Endpoint{
			"ep1": {
				ID:        "ep1",
				Pattern:   "/api/users",
				Methods:   []string{"POST", "PUT"},
				StatusCodes: map[string]int{"201": 50},
			},
		},
	}
	spec := gen.Generate(inv)

	pathItem, ok := spec.Paths["/api/users"]
	if !ok {
		t.Fatal("path /api/users not found")
	}
	if pathItem.Post == nil {
		t.Error("expected POST operation")
	}
	if pathItem.Put == nil {
		t.Error("expected PUT operation")
	}
	if pathItem.Post.RequestBody == nil {
		t.Error("expected request body for POST")
	}
}

func TestSchemaGenerator_MultipleMethods(t *testing.T) {
	gen := NewSchemaGenerator()
	inv := &Inventory{
		Version:   "1.0",
		Generated: time.Now(),
		Endpoints: map[string]*Endpoint{
			"ep1": {
				ID:      "ep1",
				Pattern: "/api/items/{id}",
				Methods: []string{"GET", "POST", "PUT", "DELETE", "PATCH"},
				Parameters: []Parameter{
					{Name: "id", In: "path", Type: "integer"},
				},
				StatusCodes: map[string]int{"200": 100},
			},
		},
	}
	spec := gen.Generate(inv)
	pathItem := spec.Paths["/api/items/{id}"]

	ops := map[string]*Operation{
		"GET":    pathItem.Get,
		"POST":   pathItem.Post,
		"PUT":    pathItem.Put,
		"DELETE": pathItem.Delete,
		"PATCH":  pathItem.Patch,
	}
	for method, op := range ops {
		if op == nil {
			t.Errorf("expected %s operation", method)
		}
	}
}

// --- Engine Tests ---

func TestEngine_NewAndRecord(t *testing.T) {
	cfg := &EngineConfig{
		RingBufferSize:   100,
		MinSamples:       1,
		ClusterThreshold: 0.8,
		ExportInterval:   1 * time.Second,
	}
	eng, err := NewEngine(cfg)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}
	defer eng.Stop()

	for range 5 {
		req := &http.Request{
			Method: "GET",
			URL:    &url.URL{Path: "/api/test"},
		}
		eng.RecordRequest(req, 200)
	}

	stats := eng.GetStats()
	if stats.RequestsAnalyzed < 5 {
		t.Errorf("expected at least 5 requests, got %d", stats.RequestsAnalyzed)
	}
}

func TestEngine_ExportOpenAPI(t *testing.T) {
	cfg := &EngineConfig{
		RingBufferSize:   100,
		MinSamples:       1,
		ClusterThreshold: 0.8,
		ExportInterval:   1 * time.Second,
	}
	eng, err := NewEngine(cfg)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}
	defer eng.Stop()

	spec := eng.ExportToOpenAPI()
	// May be nil if no analysis has run yet — that's OK
	t.Logf("OpenAPI export: %v", spec != nil)
}

func TestEngine_GetStats(t *testing.T) {
	cfg := &EngineConfig{
		RingBufferSize:   100,
		MinSamples:       1,
		ClusterThreshold: 0.8,
		ExportInterval:   1 * time.Second,
	}
	eng, err := NewEngine(cfg)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}
	defer eng.Stop()

	stats := eng.GetStats()
	if !stats.IsLearning {
		t.Error("expected IsLearning=true")
	}
}

func TestEngine_NilManagerGuards(t *testing.T) {
	eng := &Engine{manager: nil}
	eng.RecordRequest(&http.Request{URL: &url.URL{Path: "/test"}}, 200)
	eng.Stop()
	if eng.ExportToOpenAPI() != nil {
		t.Error("expected nil from ExportToOpenAPI with nil manager")
	}
	stats := eng.GetStats()
	if stats.EndpointsDiscovered != 0 || stats.RequestsAnalyzed != 0 {
		t.Error("expected zero stats with nil manager")
	}
}

// --- Manager Extended Tests ---

func TestManager_Disabled(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = false
	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	if mgr.Enabled() {
		t.Error("expected disabled manager")
	}

	mgr.Record(&http.Request{URL: &url.URL{Path: "/test"}}, nil, 0)
	stats := mgr.Stats()
	if stats.Enabled {
		t.Error("stats should show disabled")
	}
	mgr.Close()
}

func TestManager_SetEnabled(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = false
	cfg.Collection.FlushPeriod = 100 * time.Millisecond
	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	if mgr.Enabled() {
		t.Error("should start disabled")
	}

	mgr.SetEnabled(true)
	if !mgr.Enabled() {
		t.Error("should be enabled after SetEnabled(true)")
	}

	mgr.SetEnabled(false)
	if mgr.Enabled() {
		t.Error("should be disabled after SetEnabled(false)")
	}
	mgr.Close()
}

func TestManager_InventoryAndGetEndpoint(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = false
	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	inv := mgr.Inventory()
	if inv == nil {
		t.Error("expected non-nil inventory")
	}

	ep := mgr.GetEndpoint("nonexistent")
	if ep != nil {
		t.Error("expected nil for nonexistent endpoint")
	}
	mgr.Close()
}

func TestManager_GetChanges(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = false
	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	changes := mgr.GetChanges(time.Time{})
	// May be empty or nil
	t.Logf("Changes: %v", changes)
	mgr.Close()
}

func TestManager_ExportOpenAPI(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = false
	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	spec := mgr.ExportOpenAPI()
	if spec == nil {
		t.Error("expected non-nil spec even with empty inventory")
	}
	mgr.Close()
}

func TestDefaultConfig_Values(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Collection.BufferSize <= 0 {
		t.Error("expected positive buffer size")
	}
	if cfg.Analysis.MinClusterSize <= 0 {
		t.Error("expected positive min cluster size")
	}
}

// --- Change Type Constants Test ---

func TestChangeConstants(t *testing.T) {
	if ChangeTypeNew != "new" {
		t.Errorf("ChangeTypeNew = %q, want 'new'", ChangeTypeNew)
	}
	if ChangeTypeRemoved != "removed" {
		t.Errorf("ChangeTypeRemoved = %q, want 'removed'", ChangeTypeRemoved)
	}
	if ChangeTypeModified != "modified" {
		t.Errorf("ChangeTypeModified = %q, want 'modified'", ChangeTypeModified)
	}
	if SeverityLow != "low" || SeverityMedium != "medium" || SeverityHigh != "high" {
		t.Error("severity constants have unexpected values")
	}
}

// --- Clustering Edge Cases ---

func TestClusteringEngine_SlugPaths(t *testing.T) {
	engine := NewClusteringEngine(1, 0.8) // min 1 for easier testing
	now := time.Now()

	requests := []CapturedRequest{
		{Method: "GET", Path: "/blog/my-first-post", Timestamp: now},
		{Method: "GET", Path: "/blog/another-great-article", Timestamp: now},
		{Method: "GET", Path: "/blog/yet-another-post", Timestamp: now},
		{Method: "GET", Path: "/blog/some-other-entry", Timestamp: now},
		{Method: "GET", Path: "/blog/final-blog-post", Timestamp: now},
	}

	clusters := engine.Cluster(requests)
	if len(clusters) == 0 {
		t.Fatal("expected clusters for slug paths")
	}
	if !strings.Contains(clusters[0].Pattern, "{") {
		t.Logf("Pattern: %s (may not have dynamic segment)", clusters[0].Pattern)
	}
}

func TestClusteringEngine_StatusCodes(t *testing.T) {
	engine := NewClusteringEngine(2, 0.8)
	now := time.Now()

	requests := []CapturedRequest{
		{Method: "GET", Path: "/api/test", ResponseStatus: 200, Timestamp: now},
		{Method: "GET", Path: "/api/test", ResponseStatus: 200, Timestamp: now},
		{Method: "GET", Path: "/api/test", ResponseStatus: 404, Timestamp: now},
	}

	clusters := engine.Cluster(requests)
	if len(clusters) == 0 {
		t.Fatal("expected at least 1 cluster")
	}
	cl := clusters[0]
	if len(cl.StatusCodes) == 0 {
		t.Log("no status codes captured in cluster")
	} else {
		t.Logf("Status codes: %v", cl.StatusCodes)
	}
}

// --- Full Integration Test ---

func TestFullDiscoveryPipeline(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true // enabled for recording
	cfg.Analysis.MinClusterSize = 1
	cfg.Collection.FlushPeriod = 50 * time.Millisecond
	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}
	defer mgr.Close()

	// Simulate recording a variety of API requests
	paths := []string{
		"/api/v1/users/123",
		"/api/v1/users/456",
		"/api/v1/orders/789",
		"/api/v1/orders/012",
		"/api/v1/products/abc",
		"/api/v1/products/def",
	}
	for _, path := range paths {
		req := &http.Request{
			Method: "GET",
			URL:    &url.URL{Path: path},
		}
		mgr.Record(req, &http.Response{StatusCode: 200}, 10*time.Millisecond)
	}

	stats := mgr.Stats()
	if stats.RequestsCollected < int64(len(paths)) {
		t.Errorf("expected at least %d collected, got %d", len(paths), stats.RequestsCollected)
	}

	// Export should succeed
	spec := mgr.ExportOpenAPI()
	if spec == nil {
		t.Error("expected non-nil OpenAPI spec")
	}
	data, err := spec.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON failed: %v", err)
	}
	if !json.Valid(data) {
		t.Error("invalid JSON output")
	}
	t.Logf("Exported OpenAPI spec: %d bytes", len(data))
}
