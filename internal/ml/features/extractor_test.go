package features

import (
	"math"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestCalculateEntropy(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect float64
	}{
		{"empty", "", 0.0},
		{"single char", "a", 0.0},
		{"repeated", "aaaa", 0.0},
		{"two chars", "ab", 1.0 / 7.0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := calculateEntropy(tc.input)
			if math.Abs(got-tc.expect) > 0.01 {
				t.Errorf("calculateEntropy(%q) = %f, want %f", tc.input, got, tc.expect)
			}
		})
	}
}

func TestCalculateEntropy_Range(t *testing.T) {
	got := calculateEntropy(strings.Repeat("abcdefghij", 100))
	if got < 0 || got > 1.0 {
		t.Errorf("entropy out of range [0,1]: %f", got)
	}
}

func TestCountPathSegments(t *testing.T) {
	tests := []struct {
		path   string
		expect int
	}{
		{"", 0},
		{"/", 0},
		{"/api", 1},
		{"/api/v1/users", 3},
		{"/a/b/c/d", 4},
	}
	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			got := countPathSegments(tc.path)
			if got != tc.expect {
				t.Errorf("countPathSegments(%q) = %d, want %d", tc.path, got, tc.expect)
			}
		})
	}
}

func TestCountPathDepth(t *testing.T) {
	tests := []struct {
		path   string
		expect int
	}{
		{"/api/users", 0},
		{"/../etc/passwd", 1},
		{"/../../etc/passwd", 2},
		{"/..\\..\\windows\\system32", 2},
	}
	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			got := countPathDepth(tc.path)
			if got != tc.expect {
				t.Errorf("countPathDepth(%q) = %d, want %d", tc.path, got, tc.expect)
			}
		})
	}
}

func TestGetMaxQueryParamLength(t *testing.T) {
	tests := []struct {
		name   string
		query  map[string][]string
		expect int
	}{
		{"nil", nil, 0},
		{"empty", map[string][]string{}, 0},
		{"single", map[string][]string{"q": {"hello"}}, 5},
		{"multiple", map[string][]string{"a": {"xx"}, "b": {"longer"}}, 6},
		{"multi-valued", map[string][]string{"q": {"short", "verylongvalue"}}, 13},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := getMaxQueryParamLength(tc.query)
			if got != tc.expect {
				t.Errorf("got %d, want %d", got, tc.expect)
			}
		})
	}
}

func TestGetMethodRiskScore(t *testing.T) {
	tests := []struct {
		method string
		expect float64
	}{
		{"GET", 0.1},
		{"POST", 0.3},
		{"PUT", 0.5},
		{"PATCH", 0.4},
		{"DELETE", 0.7},
		{"HEAD", 0.0},
		{"OPTIONS", 0.0},
		{"UNKNOWN", 0.9},
	}
	for _, tc := range tests {
		t.Run(tc.method, func(t *testing.T) {
			got := getMethodRiskScore(tc.method)
			if got != tc.expect {
				t.Errorf("getMethodRiskScore(%q) = %f, want %f", tc.method, got, tc.expect)
			}
		})
	}
}

func TestNewExtractor(t *testing.T) {
	e := NewExtractor()
	if e == nil {
		t.Fatal("NewExtractor returned nil")
	}
	if e.maxPathSegments != 10 {
		t.Errorf("maxPathSegments = %d, want 10", e.maxPathSegments)
	}
	if e.maxBodySampleSize != 1024 {
		t.Errorf("maxBodySampleSize = %d, want 1024", e.maxBodySampleSize)
	}
}

func TestExtract_BasicRequest(t *testing.T) {
	e := NewExtractor()
	req := &http.Request{
		Method: "GET",
		URL: &url.URL{
			Path:     "/api/v1/users",
			RawQuery: "q=test&limit=10",
		},
		Header: http.Header{
			"Content-Type": {"application/json"},
			"X-Request-Id": {"abc123"},
		},
		ContentLength: 42,
	}

	fv := e.Extract(req)
	if fv == nil {
		t.Fatal("Extract returned nil")
	}

	// Path features
	if fv.PathSegmentCount != 3 {
		t.Errorf("PathSegmentCount = %f, want 3", fv.PathSegmentCount)
	}
	if fv.PathDepth != 0 {
		t.Errorf("PathDepth = %f, want 0", fv.PathDepth)
	}
	if fv.PathEntropy <= 0 {
		t.Errorf("PathEntropy should be > 0, got %f", fv.PathEntropy)
	}

	// Query features
	if fv.QueryParamCount != 2 {
		t.Errorf("QueryParamCount = %f, want 2", fv.QueryParamCount)
	}
	if fv.QueryMaxLength != 4 {
		t.Errorf("QueryMaxLength = %f, want 4 (test)", fv.QueryMaxLength)
	}

	// Header features
	if fv.HeaderCount != 2 {
		t.Errorf("HeaderCount = %f, want 2", fv.HeaderCount)
	}

	// Content length
	if fv.ContentLength != 42 {
		t.Errorf("ContentLength = %f, want 42", fv.ContentLength)
	}

	// Method score
	if fv.MethodScore != 0.1 {
		t.Errorf("MethodScore = %f, want 0.1 (GET)", fv.MethodScore)
	}

	// Body features not populated by Extract
	if fv.BodyEntropy != 0 || fv.BodySize != 0 {
		t.Errorf("body features should be 0 without ExtractWithBody")
	}
}

func TestExtract_EmptyRequest(t *testing.T) {
	e := NewExtractor()
	req := &http.Request{
		Method: "GET",
		URL:    &url.URL{Path: "/"},
		Header: http.Header{},
	}

	fv := e.Extract(req)
	if fv.PathSegmentCount != 0 {
		t.Errorf("PathSegmentCount = %f, want 0", fv.PathSegmentCount)
	}
	if fv.QueryParamCount != 0 {
		t.Errorf("QueryParamCount = %f, want 0", fv.QueryParamCount)
	}
	if fv.HeaderCount != 0 {
		t.Errorf("HeaderCount = %f, want 0", fv.HeaderCount)
	}
}

func TestExtractWithBody(t *testing.T) {
	e := NewExtractor()
	req := &http.Request{
		Method: "POST",
		URL:    &url.URL{Path: "/api/data"},
		Header: http.Header{"Content-Type": {"application/json"}},
	}

	body := []byte(`{"username":"admin","password":"secret123456789"}`)
	fv := e.ExtractWithBody(req, body)

	if fv.BodySize != float64(len(body)) {
		t.Errorf("BodySize = %f, want %d", fv.BodySize, len(body))
	}
	if fv.BodyEntropy <= 0 {
		t.Errorf("BodyEntropy should be > 0, got %f", fv.BodyEntropy)
	}
	if fv.MethodScore != 0.3 {
		t.Errorf("MethodScore = %f, want 0.3 (POST)", fv.MethodScore)
	}
}

func TestExtractWithBody_NilBody(t *testing.T) {
	e := NewExtractor()
	req := &http.Request{
		Method: "GET",
		URL:    &url.URL{Path: "/"},
		Header: http.Header{},
	}

	fv := e.ExtractWithBody(req, nil)
	if fv.BodySize != 0 {
		t.Errorf("BodySize should be 0 for nil body, got %f", fv.BodySize)
	}
	if fv.BodyEntropy != 0 {
		t.Errorf("BodyEntropy should be 0 for nil body, got %f", fv.BodyEntropy)
	}
}

func TestExtractWithBody_LargeBody(t *testing.T) {
	e := NewExtractor()
	req := &http.Request{
		Method: "POST",
		URL:    &url.URL{Path: "/upload"},
		Header: http.Header{},
	}

	largeBody := make([]byte, 5000)
	for i := range largeBody {
		largeBody[i] = byte('a' + i%26)
	}
	fv := e.ExtractWithBody(req, largeBody)

	// BodySize should be full length
	if fv.BodySize != 5000 {
		t.Errorf("BodySize = %f, want 5000", fv.BodySize)
	}
	// Entropy should be computed from sample (1024 bytes), not full body
	if fv.BodyEntropy <= 0 {
		t.Errorf("BodyEntropy should be > 0")
	}
}

func TestFeatureVector_ToSlice(t *testing.T) {
	fv := &FeatureVector{
		PathEntropy:      0.5,
		PathSegmentCount: 3,
		PathDepth:        0,
		QueryEntropy:     0.7,
		QueryParamCount:  2,
		QueryMaxLength:   10,
		HeaderCount:      5,
		HeaderEntropy:    0.3,
		ContentLength:    100,
		BodyEntropy:      0.4,
		BodySize:         200,
		MethodScore:      0.3,
		TimeOfDay:        0.5,
		DayOfWeek:        0.14,
	}

	slice := fv.ToSlice()
	if len(slice) != 14 {
		t.Fatalf("ToSlice length = %d, want 14", len(slice))
	}

	if slice[0] != 0.5 {
		t.Errorf("slice[0] (PathEntropy) = %f, want 0.5", slice[0])
	}
	if slice[1] != 3 {
		t.Errorf("slice[1] (PathSegmentCount) = %f, want 3", slice[1])
	}
	if slice[11] != 0.3 {
		t.Errorf("slice[11] (MethodScore) = %f, want 0.3", slice[11])
	}
	if slice[13] != 0.14 {
		t.Errorf("slice[13] (DayOfWeek) = %f, want 0.14", slice[13])
	}
}

func TestFeatureVector_ToSlice_ZeroValues(t *testing.T) {
	fv := &FeatureVector{}
	slice := fv.ToSlice()
	for i, v := range slice {
		if v != 0.0 {
			t.Errorf("slice[%d] = %f, want 0.0", i, v)
		}
	}
}

func TestNewNormalizer(t *testing.T) {
	n := NewNormalizer()
	if n == nil {
		t.Fatal("NewNormalizer returned nil")
	}
	if len(n.minValues) != 14 {
		t.Errorf("minValues length = %d, want 14", len(n.minValues))
	}
	if len(n.maxValues) != 14 {
		t.Errorf("maxValues length = %d, want 14", len(n.maxValues))
	}
}

func TestNormalizer_Normalize_Identity(t *testing.T) {
	// With all-zero min/max, Normalize passes through unchanged
	n := NewNormalizer()
	input := []float64{0.5, 0.3, 0.8, 0.1, 0.9, 0.2, 0.7, 0.4, 0.6, 0.0, 1.0, 0.3, 0.5, 0.14}
	output := n.Normalize(input)

	for i, v := range output {
		if v != input[i] {
			t.Errorf("output[%d] = %f, want %f (identity with zero min/max)", i, v, input[i])
		}
	}
}

func TestHeadersToString(t *testing.T) {
	h := http.Header{
		"Content-Type": {"application/json"},
		"Accept":       {"text/html"},
	}
	s := headersToString(h)
	if s == "" {
		t.Error("headersToString returned empty string")
	}
	if !strings.Contains(s, "Content-Type") {
		t.Error("missing Content-Type in output")
	}
}

func TestExtract_PathTraversal(t *testing.T) {
	e := NewExtractor()
	req := &http.Request{
		Method: "GET",
		URL:    &url.URL{Path: "/../../../etc/passwd"},
		Header: http.Header{},
	}

	fv := e.Extract(req)
	if fv.PathDepth != 3 {
		t.Errorf("PathDepth = %f, want 3 for path traversal", fv.PathDepth)
	}
}

func TestExtract_SuspiciousQuery(t *testing.T) {
	e := NewExtractor()
	req := &http.Request{
		Method: "POST",
		URL: &url.URL{
			Path:     "/login",
			RawQuery: "user=admin&pass=' OR 1=1--&redirect=http://evil.com/very/long/path/that/goes/on",
		},
		Header: http.Header{"Content-Type": {"application/x-www-form-urlencoded"}},
	}

	fv := e.Extract(req)
	if fv.QueryParamCount != 3 {
		t.Errorf("QueryParamCount = %f, want 3", fv.QueryParamCount)
	}
	if fv.QueryMaxLength < 30 {
		t.Errorf("QueryMaxLength should be large, got %f", fv.QueryMaxLength)
	}
	if fv.MethodScore != 0.3 {
		t.Errorf("MethodScore = %f, want 0.3 (POST)", fv.MethodScore)
	}
}
