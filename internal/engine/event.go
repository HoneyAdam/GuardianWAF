package engine

import (
	"sync"
	"time"
)

// UAParser is a function type for parsing User-Agent strings into structured data.
// Set via SetUAParser to avoid circular imports with the botdetect package.
type UAParser func(ua string) (browser, brVersion, os, deviceType string, isBot bool)

var (
	uaParserMu sync.RWMutex
	uaParser   UAParser
)

// SetUAParser registers a User-Agent parser function.
// Called once at startup from the main package after importing botdetect.
func SetUAParser(parser UAParser) {
	uaParserMu.Lock()
	defer uaParserMu.Unlock()
	uaParser = parser
}

func getUAParser() UAParser {
	uaParserMu.RLock()
	defer uaParserMu.RUnlock()
	return uaParser
}

// Event represents a WAF event for logging and storage.
type Event struct {
	ID         string        // Unique event ID
	Timestamp  time.Time     // When the event occurred
	RequestID  string        // Corresponding request ID
	ClientIP   string        // Client IP address
	Method     string        // HTTP method
	Path       string        // Request path
	Query      string        // Query string
	Action     Action        // WAF decision (pass/block/log)
	Score      int           // Total accumulated score
	Findings   []Finding     // All findings from detection
	Duration   time.Duration // Processing duration
	StatusCode int           // HTTP response status code
	UserAgent  string        // User-Agent header

	// Parsed User-Agent fields (populated by NewEvent)
	Browser    string // Browser name (e.g., "Chrome", "Firefox")
	BrVersion  string // Browser version (e.g., "120.0.6099.130")
	OS         string // Operating system (e.g., "Windows 10/11", "macOS 10.15.7")
	DeviceType string // Device type (e.g., "desktop", "mobile", "tablet", "bot", "cli")
	IsBot      bool   // Whether the request appears to be from a bot/scanner

	// Request metadata
	ContentType string // Content-Type header
	Referer     string // Referer header
	Host        string // Host header
}

// NewEvent creates an Event from a RequestContext after pipeline processing.
// statusCode is the HTTP response status code returned to the client.
func NewEvent(ctx *RequestContext, statusCode int) Event {
	var clientIP string
	if ctx.ClientIP != nil {
		clientIP = ctx.ClientIP.String()
	}

	var query string
	if ctx.Request != nil {
		query = ctx.Request.URL.RawQuery
	}

	var userAgent string
	if vals, ok := ctx.Headers["User-Agent"]; ok && len(vals) > 0 {
		userAgent = vals[0]
	}

	var findings []Finding
	var score int
	if ctx.Accumulator != nil {
		findings = make([]Finding, len(ctx.Accumulator.Findings()))
		copy(findings, ctx.Accumulator.Findings())
		score = ctx.Accumulator.Total()
	}

	ev := Event{
		ID:         generateRequestID(),
		Timestamp:  ctx.StartTime,
		RequestID:  ctx.RequestID,
		ClientIP:   clientIP,
		Method:     ctx.Method,
		Path:       ctx.Path,
		Query:      query,
		Action:     ctx.Action,
		Score:      score,
		Findings:   findings,
		Duration:   time.Since(ctx.StartTime),
		StatusCode: statusCode,
		UserAgent:  userAgent,
	}

	// Parse User-Agent into structured fields
	if parser := getUAParser(); parser != nil && userAgent != "" {
		ev.Browser, ev.BrVersion, ev.OS, ev.DeviceType, ev.IsBot = parser(userAgent)
	}

	// Extract additional request metadata
	if vals, ok := ctx.Headers["Content-Type"]; ok && len(vals) > 0 {
		ev.ContentType = vals[0]
	}
	if vals, ok := ctx.Headers["Referer"]; ok && len(vals) > 0 {
		ev.Referer = vals[0]
	}
	if ctx.Request != nil {
		ev.Host = ctx.Request.Host
	}

	return ev
}
