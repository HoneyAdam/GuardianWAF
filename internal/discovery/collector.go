package discovery

import (
	"bytes"
	"io"
	"math/rand"
	"net/http"
	"sync"
	"time"
)

// Collector captures HTTP requests for analysis.
type Collector struct {
	mu sync.RWMutex

	config CollectionConfig

	buffer []CapturedRequest
	head   int // Ring buffer head
	tail   int // Ring buffer tail
	size   int // Current size

	count int64 // Total requests collected
}

// CapturedRequest represents a captured HTTP request/response pair.
type CapturedRequest struct {
	Timestamp      time.Time
	Method         string
	Path           string
	RawQuery       string
	QueryParams    map[string][]string
	Headers        http.Header
	BodySample     []byte
	ResponseStatus int
	ResponseSize   int
	Latency        time.Duration
	SourceIP       string
}

// NewCollector creates a new request collector.
func NewCollector(cfg CollectionConfig) *Collector {
	return &Collector{
		config: cfg,
		buffer: make([]CapturedRequest, cfg.BufferSize),
	}
}

// Collect captures a request/response pair.
func (c *Collector) Collect(req *http.Request, resp *http.Response, latency time.Duration) {
	// Sample rate check
	if c.config.SampleRate < 1.0 && rand.Float64() > c.config.SampleRate {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Extract body sample
	bodySample := c.extractBodySample(req)

	// Extract query params
	queryParams := make(map[string][]string)
	for k, v := range req.URL.Query() {
		queryParams[k] = v
	}

	// Get source IP
	sourceIP := req.RemoteAddr
	if forwarded := req.Header.Get("X-Forwarded-For"); forwarded != "" {
		sourceIP = forwarded
	}

	captured := CapturedRequest{
		Timestamp:      time.Now(),
		Method:         req.Method,
		Path:           req.URL.Path,
		RawQuery:       req.URL.RawQuery,
		QueryParams:    queryParams,
		Headers:        req.Header.Clone(),
		BodySample:     bodySample,
		SourceIP:       sourceIP,
		Latency:        latency,
	}

	if resp != nil {
		captured.ResponseStatus = resp.StatusCode
		captured.ResponseSize = int(resp.ContentLength)
	}

	// Add to ring buffer
	c.buffer[c.head] = captured
	c.head = (c.head + 1) % len(c.buffer)
	if c.size < len(c.buffer) {
		c.size++
	} else {
		c.tail = (c.tail + 1) % len(c.buffer)
	}

	c.count++
}

// extractBodySample extracts a sample of the request body.
func (c *Collector) extractBodySample(req *http.Request) []byte {
	if req.Body == nil {
		return nil
	}

	// Read body
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil
	}

	// Restore body for later use
	req.Body = io.NopCloser(bytes.NewReader(body))

	// Return sample
	if len(body) > c.config.BodySampleSize {
		return body[:c.config.BodySampleSize]
	}
	return body
}

// Flush returns all captured requests and clears the buffer.
func (c *Collector) Flush() []CapturedRequest {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.size == 0 {
		return nil
	}

	result := make([]CapturedRequest, 0, c.size)

	if c.head > c.tail {
		// Linear
		result = append(result, c.buffer[c.tail:c.head]...)
	} else {
		// Wrapped around
		result = append(result, c.buffer[c.tail:]...)
		result = append(result, c.buffer[:c.head]...)
	}

	// Reset buffer
	c.head = 0
	c.tail = 0
	c.size = 0

	return result
}

// Peek returns captured requests without clearing.
func (c *Collector) Peek() []CapturedRequest {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.size == 0 {
		return nil
	}

	result := make([]CapturedRequest, 0, c.size)

	if c.head > c.tail {
		result = append(result, c.buffer[c.tail:c.head]...)
	} else {
		result = append(result, c.buffer[c.tail:]...)
		result = append(result, c.buffer[:c.head]...)
	}

	return result
}

// Count returns total requests collected.
func (c *Collector) Count() int64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.count
}

// Size returns current buffer size.
func (c *Collector) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.size
}

// Clear clears the buffer.
func (c *Collector) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.head = 0
	c.tail = 0
	c.size = 0
}
