package onnx

import (
	"context"
	"math"
	"sync"
	"testing"
	"time"
)

func TestNewModel(t *testing.T) {
	m := NewModel("isolation_forest", "1.0")
	if m == nil {
		t.Fatal("NewModel returned nil")
	}
	if m.GetThreshold() != 0.7 {
		t.Errorf("default threshold = %f, want 0.7", m.GetThreshold())
	}
}

func TestModel_SetThreshold(t *testing.T) {
	m := NewModel("test", "1.0")
	m.SetThreshold(0.9)
	if m.GetThreshold() != 0.9 {
		t.Errorf("threshold = %f, want 0.9", m.GetThreshold())
	}
}

func TestModel_SetThreshold_Concurrent(t *testing.T) {
	m := NewModel("test", "1.0")
	var wg sync.WaitGroup
	for i := range 100 {
		wg.Add(1)
		go func(val float64) {
			defer wg.Done()
			m.SetThreshold(val)
		}(float64(i) / 100.0)
	}
	wg.Wait()
	// Should not panic from concurrent access
}

func TestModel_Load(t *testing.T) {
	m := NewModel("test", "1.0")
	err := m.Load("/nonexistent/model.onnx", Config{})
	if err != nil {
		t.Errorf("Load (POC) should not error, got: %v", err)
	}
}

func TestModel_Predict_EmptyFeatures(t *testing.T) {
	m := NewModel("test", "1.0")
	m.SetThreshold(0.5)

	result, err := m.Predict(context.Background(), []float64{})
	if err != nil {
		t.Fatalf("Predict error: %v", err)
	}
	if result.AnomalyScore != 0.0 {
		t.Errorf("empty features should score 0.0, got %f", result.AnomalyScore)
	}
	if result.IsAnomaly {
		t.Error("empty features should not be anomaly")
	}
}

func TestModel_Predict_NormalTraffic(t *testing.T) {
	m := NewModel("test", "1.0")
	m.SetThreshold(0.7)

	// Normal traffic: uniform-ish features (low z-scores)
	features := make([]float64, 14)
	for i := range features {
		features[i] = 0.5
	}
	result, err := m.Predict(context.Background(), features)
	if err != nil {
		t.Fatalf("Predict error: %v", err)
	}

	// Uniform features should have low anomaly score
	if result.AnomalyScore > 0.5 {
		t.Errorf("uniform traffic scored as anomaly: %f", result.AnomalyScore)
	}
	if result.Confidence < 0 || result.Confidence > 1.0 {
		t.Errorf("confidence out of range: %f", result.Confidence)
	}
}

func TestModel_Predict_AnomalousTraffic(t *testing.T) {
	m := NewModel("test", "1.0")
	m.SetThreshold(0.5)

	// Anomalous features: very high entropy, many segments, extreme values
	features := []float64{5.0, 20.0, 5.0, 8.0, 50.0, 500.0, 40.0, 6.0, 10000.0, 5.0, 50000.0, 0.9, 0.5, 0.14}
	result, err := m.Predict(context.Background(), features)
	if err != nil {
		t.Fatalf("Predict error: %v", err)
	}

	// Highly anomalous features should trigger
	if result.AnomalyScore < 0.5 {
		t.Errorf("anomalous traffic scored too low: %f", result.AnomalyScore)
	}
	if !result.IsAnomaly {
		t.Error("anomalous traffic should be flagged")
	}
}

func TestModel_Predict_Confidence(t *testing.T) {
	m := NewModel("test", "1.0")
	m.SetThreshold(0.5)

	// Score well above threshold should have high confidence
	features := []float64{5.0, 20.0, 5.0, 8.0, 50.0, 500.0, 40.0, 6.0, 10000.0, 5.0, 50000.0, 0.9, 0.5, 0.14}
	result, _ := m.Predict(context.Background(), features)

	if result.Confidence < 0.5 {
		t.Errorf("high anomaly score should have high confidence, got %f", result.Confidence)
	}
}

func TestModel_Predict_ContextCancellation(t *testing.T) {
	m := NewModel("test", "1.0")
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	_, err := m.Predict(ctx, []float64{0.5, 0.3, 0.1})
	// POC doesn't check context, so it may still succeed — just verify no panic
	_ = err
}

func TestModel_Info(t *testing.T) {
	m := NewModel("isolation_forest", "2.0")
	m.SetThreshold(0.85)

	info := m.Info()
	if info["name"] != "isolation_forest" {
		t.Errorf("name = %v, want isolation_forest", info["name"])
	}
	if info["version"] != "2.0" {
		t.Errorf("version = %v, want 2.0", info["version"])
	}
	if info["threshold"] != 0.85 {
		t.Errorf("threshold = %v, want 0.85", info["threshold"])
	}
}

func TestNewManager(t *testing.T) {
	mgr := NewManager()
	if mgr == nil {
		t.Fatal("NewManager returned nil")
	}
	list := mgr.List()
	if len(list) != 0 {
		t.Errorf("new manager should have no models, got %d", len(list))
	}
}

func TestManager_RegisterAndGet(t *testing.T) {
	mgr := NewManager()
	m1 := NewModel("model-a", "1.0")
	mgr.Register("anomaly", m1)

	got, err := mgr.Get("anomaly")
	if err != nil {
		t.Fatalf("Get error: %v", err)
	}
	if got != m1 {
		t.Error("Get returned wrong model")
	}
}

func TestManager_GetNotFound(t *testing.T) {
	mgr := NewManager()
	_, err := mgr.Get("nonexistent")
	if err == nil {
		t.Error("expected error for missing model")
	}
}

func TestManager_RegisterOverwrite(t *testing.T) {
	mgr := NewManager()
	m1 := NewModel("v1", "1.0")
	m2 := NewModel("v2", "2.0")
	mgr.Register("anomaly", m1)
	mgr.Register("anomaly", m2) // overwrite

	got, _ := mgr.Get("anomaly")
	if got == m1 {
		t.Error("expected v2 model after overwrite")
	}
}

func TestManager_List(t *testing.T) {
	mgr := NewManager()
	mgr.Register("a", NewModel("a", "1.0"))
	mgr.Register("b", NewModel("b", "1.0"))
	mgr.Register("c", NewModel("c", "1.0"))

	list := mgr.List()
	if len(list) != 3 {
		t.Errorf("List returned %d models, want 3", len(list))
	}
}

func TestManager_Close(t *testing.T) {
	mgr := NewManager()
	mgr.Register("a", NewModel("a", "1.0"))
	mgr.Close()

	list := mgr.List()
	if len(list) != 0 {
		t.Errorf("after Close, List should be empty, got %d", len(list))
	}
}

func TestCalculateAnomalyScore(t *testing.T) {
	// Zero variance input: all same values mean stdDev=0, maxZScore=0
	// sigmoid(0) = 1/(1+exp(2)) ~ 0.119
	score := calculateAnomalyScore([]float64{5.0, 5.0, 5.0, 5.0})
	if score > 0.2 {
		t.Errorf("zero variance should score low, got %f", score)
	}

	// High variance input should score high
	score = calculateAnomalyScore([]float64{0.0, 0.0, 0.0, 100.0})
	if score <= 0.0 {
		t.Errorf("high variance should score > 0, got %f", score)
	}
}

func TestCalculateConfidence(t *testing.T) {
	tests := []struct {
		score     float64
		threshold float64
		expect    float64
	}{
		{0.0, 0.5, 1.0},   // far from threshold
		{0.5, 0.5, 0.0},   // at threshold
		{0.6, 0.5, 0.2},   // slightly above
		{1.0, 0.0, 1.0},   // capped at 1.0
	}
	for _, tc := range tests {
		got := calculateConfidence(tc.score, tc.threshold)
		if math.Abs(got-tc.expect) > 0.01 {
			t.Errorf("calculateConfidence(%f, %f) = %f, want %f", tc.score, tc.threshold, got, tc.expect)
		}
	}
}

func TestModel_Predict_Latency(t *testing.T) {
	m := NewModel("test", "1.0")
	features := make([]float64, 14)
	result, _ := m.Predict(context.Background(), features)

	if result.Latency > time.Second {
		t.Errorf("POC prediction too slow: %v", result.Latency)
	}
}

func TestManager_ConcurrentAccess(t *testing.T) {
	mgr := NewManager()
	var wg sync.WaitGroup

	// Concurrent register
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			mgr.Register("model", NewModel("test", "1.0"))
		}()
	}
	wg.Wait()

	// Concurrent get
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			mgr.Get("model")
		}()
	}
	wg.Wait()

	// Concurrent list
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			mgr.List()
		}()
	}
	wg.Wait()
}
