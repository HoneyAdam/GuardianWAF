package analytics

import (
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Counter tests
// ---------------------------------------------------------------------------

func TestCounterAddAndTotal(t *testing.T) {
	c := NewCounter(10*time.Second, 1*time.Second)

	c.Add(5)
	c.Add(3)

	total := c.Total()
	if total != 8 {
		t.Fatalf("expected total 8, got %d", total)
	}
}

func TestCounterReset(t *testing.T) {
	c := NewCounter(10*time.Second, 1*time.Second)
	c.Add(100)
	c.Reset()

	if total := c.Total(); total != 0 {
		t.Fatalf("expected 0 after reset, got %d", total)
	}
}

func TestCounterNewDefaults(t *testing.T) {
	// step > window should default to window
	c := NewCounter(5*time.Second, 10*time.Second)
	c.Add(1)
	if c.Total() != 1 {
		t.Fatalf("expected 1, got %d", c.Total())
	}

	// zero step
	c2 := NewCounter(5*time.Second, 0)
	c2.Add(42)
	if c2.Total() != 42 {
		t.Fatalf("expected 42, got %d", c2.Total())
	}
}

func TestCounterMultipleBuckets(t *testing.T) {
	c := NewCounter(4*time.Second, 1*time.Second)
	// Add to the initial bucket
	c.Add(10)

	total := c.Total()
	if total != 10 {
		t.Fatalf("expected 10, got %d", total)
	}
}

// ---------------------------------------------------------------------------
// TopK tests
// ---------------------------------------------------------------------------

func TestTopKAdd(t *testing.T) {
	tk := NewTopK(3)

	tk.Add("a", 10)
	tk.Add("b", 20)
	tk.Add("c", 5)
	tk.Add("d", 15)

	top := tk.Top()
	if len(top) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(top))
	}

	if top[0].Key != "b" || top[0].Count != 20 {
		t.Fatalf("expected top entry b:20, got %s:%d", top[0].Key, top[0].Count)
	}
	if top[1].Key != "d" || top[1].Count != 15 {
		t.Fatalf("expected second entry d:15, got %s:%d", top[1].Key, top[1].Count)
	}
	if top[2].Key != "a" || top[2].Count != 10 {
		t.Fatalf("expected third entry a:10, got %s:%d", top[2].Key, top[2].Count)
	}
}

func TestTopKIncrement(t *testing.T) {
	tk := NewTopK(5)
	tk.Add("x", 1)
	tk.Add("x", 1)
	tk.Add("x", 1)

	if c := tk.Count("x"); c != 3 {
		t.Fatalf("expected count 3, got %d", c)
	}
}

func TestTopKReset(t *testing.T) {
	tk := NewTopK(5)
	tk.Add("a", 10)
	tk.Reset()

	if len(tk.Top()) != 0 {
		t.Fatal("expected empty after reset")
	}
}

func TestTopKDefaultK(t *testing.T) {
	tk := NewTopK(0)
	for i := 0; i < 20; i++ {
		tk.Add(string(rune('a'+i)), int64(i))
	}
	top := tk.Top()
	if len(top) != 10 {
		t.Fatalf("expected 10 (default k), got %d", len(top))
	}
}

// ---------------------------------------------------------------------------
// TimeSeries tests
// ---------------------------------------------------------------------------

func TestTimeSeriesAddAndPoints(t *testing.T) {
	ts := NewTimeSeries(5)

	now := time.Now()
	for i := 0; i < 5; i++ {
		ts.Add(now.Add(time.Duration(i)*time.Second), float64(i))
	}

	points := ts.Points()
	if len(points) != 5 {
		t.Fatalf("expected 5 points, got %d", len(points))
	}

	// Should be chronological
	for i := 0; i < 5; i++ {
		if points[i].Value != float64(i) {
			t.Fatalf("point %d: expected value %f, got %f", i, float64(i), points[i].Value)
		}
	}
}

func TestTimeSeriesOverflow(t *testing.T) {
	ts := NewTimeSeries(3)

	now := time.Now()
	for i := 0; i < 5; i++ {
		ts.Add(now.Add(time.Duration(i)*time.Second), float64(i))
	}

	points := ts.Points()
	if len(points) != 3 {
		t.Fatalf("expected 3 points, got %d", len(points))
	}

	// Should have the last 3: 2, 3, 4
	expected := []float64{2, 3, 4}
	for i, exp := range expected {
		if points[i].Value != exp {
			t.Fatalf("point %d: expected %f, got %f", i, exp, points[i].Value)
		}
	}
}

func TestTimeSeriesLast(t *testing.T) {
	ts := NewTimeSeries(10)

	_, ok := ts.Last()
	if ok {
		t.Fatal("expected no last point for empty series")
	}

	now := time.Now()
	ts.Add(now, 42.0)

	pt, ok := ts.Last()
	if !ok {
		t.Fatal("expected last point")
	}
	if pt.Value != 42.0 {
		t.Fatalf("expected 42.0, got %f", pt.Value)
	}
}

func TestTimeSeriesLen(t *testing.T) {
	ts := NewTimeSeries(5)
	if ts.Len() != 0 {
		t.Fatalf("expected 0, got %d", ts.Len())
	}

	now := time.Now()
	ts.Add(now, 1)
	ts.Add(now, 2)

	if ts.Len() != 2 {
		t.Fatalf("expected 2, got %d", ts.Len())
	}
}

func TestTimeSeriesReset(t *testing.T) {
	ts := NewTimeSeries(5)
	now := time.Now()
	ts.Add(now, 1)
	ts.Add(now, 2)
	ts.Reset()

	if ts.Len() != 0 {
		t.Fatalf("expected 0 after reset, got %d", ts.Len())
	}
	if pts := ts.Points(); pts != nil {
		t.Fatalf("expected nil points after reset, got %v", pts)
	}
}

func TestTimeSeriesDefaultSize(t *testing.T) {
	ts := NewTimeSeries(0)
	// default should be 60
	now := time.Now()
	for i := 0; i < 100; i++ {
		ts.Add(now.Add(time.Duration(i)*time.Second), float64(i))
	}
	if ts.Len() != 60 {
		t.Fatalf("expected 60, got %d", ts.Len())
	}
}

func TestTimeSeriesEmptyPoints(t *testing.T) {
	ts := NewTimeSeries(5)
	if pts := ts.Points(); pts != nil {
		t.Fatalf("expected nil for empty series, got %v", pts)
	}
}

// ---------------------------------------------------------------------------
// Additional Counter coverage tests
// ---------------------------------------------------------------------------

func TestCounterWindowRotation(t *testing.T) {
	// Use small window/step that we can manipulate
	c := NewCounter(200*time.Millisecond, 50*time.Millisecond)
	c.Add(10)

	// Wait for one step to elapse
	time.Sleep(60 * time.Millisecond)
	c.Add(20)

	total := c.Total()
	if total != 30 {
		t.Fatalf("expected 30, got %d", total)
	}
}

func TestCounterFullWindowExpiration(t *testing.T) {
	c := NewCounter(100*time.Millisecond, 25*time.Millisecond)
	c.Add(100)

	// Wait for entire window to pass
	time.Sleep(150 * time.Millisecond)

	total := c.Total()
	if total != 0 {
		t.Fatalf("expected 0 after full window expiration, got %d", total)
	}
}

func TestCounterConcurrentAdd(t *testing.T) {
	c := NewCounter(10*time.Second, 1*time.Second)

	var wg sync.WaitGroup
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 100 {
				c.Add(1)
			}
		}()
	}
	wg.Wait()

	total := c.Total()
	if total != 1000 {
		t.Fatalf("expected 1000, got %d", total)
	}
}

func TestCounterPartialRotation(t *testing.T) {
	c := NewCounter(200*time.Millisecond, 50*time.Millisecond)

	// Add to bucket 0
	c.Add(10)

	// Wait for 2 steps
	time.Sleep(110 * time.Millisecond)

	// Add to a new bucket
	c.Add(20)

	total := c.Total()
	// Both values should still be within the window
	if total != 30 {
		t.Fatalf("expected 30, got %d", total)
	}
}

func TestCounterNegativeStep(t *testing.T) {
	// Negative step should default to window
	c := NewCounter(5*time.Second, -1*time.Second)
	c.Add(7)
	if c.Total() != 7 {
		t.Fatalf("expected 7, got %d", c.Total())
	}
}

// ---------------------------------------------------------------------------
// Additional TopK coverage tests
// ---------------------------------------------------------------------------

func TestTopKPruning(t *testing.T) {
	// k=2 means prune triggers at 2*10=20 entries
	tk := NewTopK(2)

	// Add 21 unique keys to trigger pruning
	for i := 0; i < 21; i++ {
		tk.Add(string(rune('a'+i%26))+intToStr(i), int64(i))
	}

	// After pruning, we should have at most ~2 keys in the map
	top := tk.Top()
	if len(top) != 2 {
		t.Fatalf("expected 2 top entries, got %d", len(top))
	}

	// The top entries should be the highest counts
	if top[0].Count < top[1].Count {
		t.Error("expected descending order")
	}
}

func TestTopKTies(t *testing.T) {
	tk := NewTopK(5)
	tk.Add("alpha", 10)
	tk.Add("beta", 10)
	tk.Add("gamma", 10)

	top := tk.Top()
	if len(top) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(top))
	}

	// With equal counts, should be sorted by key alphabetically
	if top[0].Key != "alpha" {
		t.Errorf("expected 'alpha' first (alphabetical), got %q", top[0].Key)
	}
	if top[1].Key != "beta" {
		t.Errorf("expected 'beta' second, got %q", top[1].Key)
	}
	if top[2].Key != "gamma" {
		t.Errorf("expected 'gamma' third, got %q", top[2].Key)
	}
}

func TestTopKSingleItem(t *testing.T) {
	tk := NewTopK(5)
	tk.Add("only", 42)

	top := tk.Top()
	if len(top) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(top))
	}
	if top[0].Key != "only" || top[0].Count != 42 {
		t.Errorf("expected only:42, got %s:%d", top[0].Key, top[0].Count)
	}
}

func TestTopKCountMissing(t *testing.T) {
	tk := NewTopK(5)
	if c := tk.Count("nonexistent"); c != 0 {
		t.Fatalf("expected 0 for missing key, got %d", c)
	}
}

func TestTopKEmpty(t *testing.T) {
	tk := NewTopK(5)
	top := tk.Top()
	if len(top) != 0 {
		t.Fatalf("expected 0 entries, got %d", len(top))
	}
}

func TestTopKNegativeK(t *testing.T) {
	tk := NewTopK(-5)
	for i := 0; i < 20; i++ {
		tk.Add(string(rune('a'+i)), int64(i))
	}
	top := tk.Top()
	if len(top) != 10 {
		t.Fatalf("expected 10 (default k) for negative k, got %d", len(top))
	}
}

// ---------------------------------------------------------------------------
// Additional TimeSeries coverage tests
// ---------------------------------------------------------------------------

func TestTimeSeriesWrapAround(t *testing.T) {
	ts := NewTimeSeries(3)
	now := time.Now()

	// Add 7 points (wraps around multiple times)
	for i := 0; i < 7; i++ {
		ts.Add(now.Add(time.Duration(i)*time.Second), float64(i))
	}

	points := ts.Points()
	if len(points) != 3 {
		t.Fatalf("expected 3 points, got %d", len(points))
	}

	// Should have the last 3: 4, 5, 6 in chronological order
	expected := []float64{4, 5, 6}
	for i, exp := range expected {
		if points[i].Value != exp {
			t.Errorf("point %d: expected %f, got %f", i, exp, points[i].Value)
		}
	}
}

func TestTimeSeriesLastAfterOverflow(t *testing.T) {
	ts := NewTimeSeries(3)
	now := time.Now()

	for i := 0; i < 10; i++ {
		ts.Add(now.Add(time.Duration(i)*time.Second), float64(i))
	}

	pt, ok := ts.Last()
	if !ok {
		t.Fatal("expected last point")
	}
	if pt.Value != 9.0 {
		t.Fatalf("expected 9.0, got %f", pt.Value)
	}
}

func TestTimeSeriesPointsOrderAfterWrap(t *testing.T) {
	ts := NewTimeSeries(4)
	now := time.Now()

	// Fill exactly: 0, 1, 2, 3
	for i := 0; i < 4; i++ {
		ts.Add(now.Add(time.Duration(i)*time.Second), float64(i))
	}

	// Add 2 more: overwrites 0 and 1
	ts.Add(now.Add(4*time.Second), 4.0)
	ts.Add(now.Add(5*time.Second), 5.0)

	points := ts.Points()
	if len(points) != 4 {
		t.Fatalf("expected 4 points, got %d", len(points))
	}

	// Should be 2, 3, 4, 5 in chronological order
	expected := []float64{2, 3, 4, 5}
	for i, exp := range expected {
		if points[i].Value != exp {
			t.Errorf("point %d: expected %f, got %f", i, exp, points[i].Value)
		}
	}
}

func TestTimeSeriesResetThenAdd(t *testing.T) {
	ts := NewTimeSeries(5)
	now := time.Now()

	ts.Add(now, 1.0)
	ts.Add(now.Add(time.Second), 2.0)
	ts.Reset()

	ts.Add(now.Add(2*time.Second), 3.0)
	if ts.Len() != 1 {
		t.Fatalf("expected 1 after reset+add, got %d", ts.Len())
	}

	pt, ok := ts.Last()
	if !ok {
		t.Fatal("expected last point")
	}
	if pt.Value != 3.0 {
		t.Fatalf("expected 3.0, got %f", pt.Value)
	}

	points := ts.Points()
	if len(points) != 1 {
		t.Fatalf("expected 1 point, got %d", len(points))
	}
	if points[0].Value != 3.0 {
		t.Fatalf("expected 3.0, got %f", points[0].Value)
	}
}

func TestTimeSeriesNegativeSize(t *testing.T) {
	ts := NewTimeSeries(-10)
	// Default should be 60
	now := time.Now()
	for i := 0; i < 100; i++ {
		ts.Add(now.Add(time.Duration(i)*time.Second), float64(i))
	}
	if ts.Len() != 60 {
		t.Fatalf("expected 60 for negative size, got %d", ts.Len())
	}
}

// helper for TopK tests
func intToStr(n int) string {
	if n == 0 {
		return "0"
	}
	if n < 0 {
		return "-" + intToStr(-n)
	}
	var digits [20]byte
	i := len(digits)
	for n > 0 {
		i--
		digits[i] = byte(n%10) + '0'
		n /= 10
	}
	return string(digits[i:])
}
