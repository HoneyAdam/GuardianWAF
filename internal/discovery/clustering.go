package discovery

import (
	"regexp"
	"strings"
)

// Cluster represents a group of similar API endpoints.
type Cluster struct {
	Pattern     string          // /api/users/{id}
	PathRegex   *regexp.Regexp  // Compiled regex for matching
	Examples    []string        // Sample paths
	Count       int             // Total requests
	Methods     map[string]int  // Method distribution
	Parameters  []Parameter     // Discovered parameters
	FirstSeen   int64           // Unix timestamp
	LastSeen    int64           // Unix timestamp
	StatusCodes map[int]int     // Response status distribution
}

// Parameter represents a discovered API parameter.
type Parameter struct {
	Name       string   `json:"name"`
	In         string   `json:"in"`      // "path", "query", "header"
	Type       string   `json:"type"`    // "string", "integer", "boolean"
	Required   bool     `json:"required"`
	Pattern    string   `json:"pattern,omitempty"`
	Enum       []string `json:"enum,omitempty"`
	Example    string   `json:"example,omitempty"`
	Frequency  int      `json:"frequency"`
}

// ClusteringEngine groups similar paths into endpoint patterns.
type ClusteringEngine struct {
	minClusterSize      int
	similarityThreshold float64
	maxClusters         int
}

// NewClusteringEngine creates a new clustering engine.
func NewClusteringEngine(minSize int, threshold float64) *ClusteringEngine {
	return &ClusteringEngine{
		minClusterSize:      minSize,
		similarityThreshold: threshold,
		maxClusters:         1000,
	}
}

// Cluster groups paths into endpoint patterns.
func (e *ClusteringEngine) Cluster(requests []CapturedRequest) []Cluster {
	// Group by method + path pattern candidate
	pathGroups := e.groupByBasePath(requests)

	var clusters []Cluster

	for _, group := range pathGroups {
		if len(group) < e.minClusterSize {
			continue
		}

		cluster := e.createCluster(group)
		if cluster != nil {
			clusters = append(clusters, *cluster)
		}
	}

	return clusters
}

// groupByBasePath groups requests by their base path structure.
func (e *ClusteringEngine) groupByBasePath(requests []CapturedRequest) map[string][]CapturedRequest {
	groups := make(map[string][]CapturedRequest)

	for _, req := range requests {
		basePath := e.getBasePath(req.Path)
		key := req.Method + " " + basePath
		groups[key] = append(groups[key], req)
	}

	return groups
}

// getBasePath extracts the base path (without dynamic segments).
func (e *ClusteringEngine) getBasePath(path string) string {
	segments := splitPath(path)

	// Replace potential dynamic segments with placeholders
	for i, seg := range segments {
		if isDynamicSegment(seg) {
			segments[i] = "{}"
		}
	}

	return strings.Join(segments, "/")
}

// createCluster creates a cluster from a group of requests.
func (e *ClusteringEngine) createCluster(requests []CapturedRequest) *Cluster {
	if len(requests) == 0 {
		return nil
	}

	// Analyze paths to identify pattern
	pathPattern, dynamicSegments := e.inferPattern(requests)

	// Build regex
	regex := e.buildPathRegex(pathPattern, dynamicSegments)

	// Collect examples
	examples := make([]string, 0, 10)
	seen := make(map[string]bool)
	for _, req := range requests {
		if !seen[req.Path] && len(examples) < 10 {
			examples = append(examples, req.Path)
			seen[req.Path] = true
		}
	}

	// Method distribution
	methods := make(map[string]int)
	for _, req := range requests {
		methods[req.Method]++
	}

	// Status code distribution
	statusCodes := make(map[int]int)
	for _, req := range requests {
		statusCodes[req.ResponseStatus]++
	}

	// Extract parameters
	parameters := e.extractParameters(requests, dynamicSegments)

	cluster := &Cluster{
		Pattern:     pathPattern,
		PathRegex:   regex,
		Examples:    examples,
		Count:       len(requests),
		Methods:     methods,
		Parameters:  parameters,
		StatusCodes: statusCodes,
		FirstSeen:   requests[0].Timestamp.Unix(),
		LastSeen:    requests[len(requests)-1].Timestamp.Unix(),
	}

	return cluster
}

// inferPattern infers the endpoint pattern and identifies dynamic segments.
func (e *ClusteringEngine) inferPattern(requests []CapturedRequest) (string, []DynamicSegment) {
	if len(requests) == 0 {
		return "", nil
	}

	// Get sample paths
	paths := make([]string, 0, len(requests))
	for _, req := range requests {
		paths = append(paths, req.Path)
	}

	// Tokenize paths
	tokenized := make([][]string, len(paths))
	for i, path := range paths {
		tokenized[i] = splitPath(path)
	}

	if len(tokenized) == 0 {
		return "", nil
	}

	// Identify segment count
	segmentCount := len(tokenized[0])

	// Analyze each segment position
	var dynamicSegments []DynamicSegment
	patternSegments := make([]string, segmentCount)

	for pos := 0; pos < segmentCount; pos++ {
		// Collect all values at this position
		values := make([]string, len(tokenized))
		for i, tokens := range tokenized {
			if pos < len(tokens) {
				values[i] = tokens[pos]
			}
		}

		// Check if this position is dynamic
		if e.isDynamicPosition(values) {
			segmentType := e.inferSegmentType(values)
			patternSegments[pos] = "{" + segmentType + "}"
			dynamicSegments = append(dynamicSegments, DynamicSegment{
				Position: pos,
				Type:     segmentType,
				Pattern:  e.getPatternForType(segmentType),
			})
		} else {
			patternSegments[pos] = values[0]
		}
	}

	return "/" + strings.Join(patternSegments, "/"), dynamicSegments
}

// DynamicSegment represents a dynamic path segment.
type DynamicSegment struct {
	Position int
	Type     string
	Pattern  string
}

// isDynamicPosition determines if a segment position is dynamic.
func (e *ClusteringEngine) isDynamicPosition(values []string) bool {
	if len(values) < 2 {
		return false
	}

	// Check uniqueness
	unique := make(map[string]int)
	for _, v := range values {
		unique[v]++
	}

	// If more than 50% are unique, consider dynamic
	uniqueRatio := float64(len(unique)) / float64(len(values))
	return uniqueRatio > 0.5
}

// inferSegmentType infers the type of a dynamic segment.
func (e *ClusteringEngine) inferSegmentType(values []string) string {
	intCount := 0
	uuidCount := 0
	slugCount := 0

	for _, v := range values {
		switch {
		case isInteger(v):
			intCount++
		case isUUID(v):
			uuidCount++
		case isSlug(v):
			slugCount++
		}
	}

	total := float64(len(values))

	if float64(intCount)/total > 0.8 {
		return "id"
	}
	if float64(uuidCount)/total > 0.8 {
		return "uuid"
	}
	if float64(slugCount)/total > 0.8 {
		return "slug"
	}

	return "id"
}

// buildPathRegex builds a regex pattern for path matching.
func (e *ClusteringEngine) buildPathRegex(pattern string, dynamicSegments []DynamicSegment) *regexp.Regexp {
	// Escape the pattern and replace placeholders with regex
	escaped := regexp.QuoteMeta(pattern)

	// Replace placeholders with actual patterns
	for _, seg := range dynamicSegments {
		placeholder := regexp.QuoteMeta("{" + seg.Type + "}")
		escaped = strings.Replace(escaped, placeholder, seg.Pattern, 1)
	}

	// Anchor the pattern
	escaped = "^" + escaped + "$"

	re, err := regexp.Compile(escaped)
	if err != nil {
		// Fallback to simple matching
		return regexp.MustCompile(".*")
	}

	return re
}

// getPatternForType returns the regex pattern for a segment type.
func (e *ClusteringEngine) getPatternForType(segType string) string {
	switch segType {
	case "id":
		return `[^/]+`
	case "uuid":
		return `[0-9a-f-]{36}`
	case "slug":
		return `[a-z0-9-]+`
	default:
		return `[^/]+`
	}
}

// extractParameters extracts parameters from requests.
func (e *ClusteringEngine) extractParameters(requests []CapturedRequest, dynamicSegments []DynamicSegment) []Parameter {
	var params []Parameter

	// Path parameters
	for _, seg := range dynamicSegments {
		param := Parameter{
			Name:      seg.Type,
			In:        "path",
			Type:      e.segmentTypeToDataType(seg.Type),
			Required:  true,
			Pattern:   e.getPatternForType(seg.Type),
			Frequency: len(requests),
		}
		params = append(params, param)
	}

	// Query parameters
	queryParams := e.extractQueryParameters(requests)
	params = append(params, queryParams...)

	return params
}

// extractQueryParameters extracts query parameters.
func (e *ClusteringEngine) extractQueryParameters(requests []CapturedRequest) []Parameter {
	paramStats := make(map[string]*parameterStat)

	for _, req := range requests {
		for name, values := range req.QueryParams {
			if _, ok := paramStats[name]; !ok {
				paramStats[name] = &parameterStat{
					name:     name,
					values:   make(map[string]int),
					types:    make(map[string]int),
					required: true,
				}
			}

			stat := paramStats[name]
			for _, v := range values {
				stat.values[v]++
				stat.types[inferDataType(v)]++
			}
		}
	}

	var params []Parameter
	for _, stat := range paramStats {
		// Check if optional (not present in all requests)
		if len(requests) > len(stat.values)*2 {
			stat.required = false
		}

		// Determine most common type
		paramType := "string"
		maxCount := 0
		for t, count := range stat.types {
			if count > maxCount {
				maxCount = count
				paramType = t
			}
		}

		// Extract enum if small set
		var enum []string
		if len(stat.values) <= 10 {
			for v := range stat.values {
				enum = append(enum, v)
			}
		}

		param := Parameter{
			Name:      stat.name,
			In:        "query",
			Type:      paramType,
			Required:  stat.required,
			Enum:      enum,
			Frequency: len(requests),
		}
		params = append(params, param)
	}

	return params
}

// parameterStat tracks parameter statistics.
type parameterStat struct {
	name     string
	values   map[string]int
	types    map[string]int
	required bool
}

// segmentTypeToDataType converts segment type to data type.
func (e *ClusteringEngine) segmentTypeToDataType(segType string) string {
	switch segType {
	case "id":
		return "integer"
	case "uuid":
		return "string"
	case "slug":
		return "string"
	default:
		return "string"
	}
}

// Helper functions

func splitPath(path string) []string {
	path = strings.Trim(path, "/")
	if path == "" {
		return []string{}
	}
	return strings.Split(path, "/")
}

func isDynamicSegment(seg string) bool {
	return isInteger(seg) || isUUID(seg) || isHash(seg)
}

func isInteger(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func isUUID(s string) bool {
	pattern := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	return pattern.MatchString(strings.ToLower(s))
}

func isSlug(s string) bool {
	pattern := regexp.MustCompile(`^[a-z0-9-]+$`)
	return pattern.MatchString(s)
}

func isHash(s string) bool {
	// Check for common hash patterns (md5, sha1, sha256)
	if len(s) != 32 && len(s) != 40 && len(s) != 64 {
		return false
	}
	pattern := regexp.MustCompile(`^[a-f0-9]+$`)
	return pattern.MatchString(strings.ToLower(s))
}

func inferDataType(value string) string {
	if isInteger(value) {
		return "integer"
	}
	if value == "true" || value == "false" {
		return "boolean"
	}
	return "string"
}
