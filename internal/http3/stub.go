//go:build !http3

// Package http3 provides HTTP/3 stub when the http3 build tag is not enabled.
// This allows the code to compile without the quic-go dependency.
package http3

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"time"
)

// Config holds HTTP/3 server configuration (stub).
type Config struct {
	Enabled           bool          `yaml:"enabled"`
	Listen            string        `yaml:"listen"`
	MaxHeaderBytes    int           `yaml:"max_header_bytes"`
	ReadTimeout       time.Duration `yaml:"read_timeout"`
	WriteTimeout      time.Duration `yaml:"write_timeout"`
	IdleTimeout       time.Duration `yaml:"idle_timeout"`
	Enable0RTT        bool          `yaml:"enable_0rtt"`
	EnableDatagrams   bool          `yaml:"enable_datagrams"`
	AltSvcPort        int           `yaml:"alt_svc_port"`
	AltSvcProtocol    string        `yaml:"alt_svc_protocol"`
	MaxRequestBodySize int64        `yaml:"max_request_body_size"`
}

// DefaultConfig returns default HTTP/3 configuration (stub).
func DefaultConfig() *Config {
	return &Config{
		Enabled: false,
	}
}

// Server is a stub HTTP/3 server.
type Server struct {
	config *Config
}

// NewServer creates a stub HTTP/3 server that returns an error.
func NewServer(cfg *Config, handler http.Handler, tlsConfig *tls.Config) (*Server, error) {
	if cfg != nil && cfg.Enabled {
		return nil, fmt.Errorf("HTTP/3 is enabled but GuardianWAF was built without HTTP/3 support. " +
			"Rebuild with: go build -tags http3")
	}
	return &Server{config: cfg}, nil
}

// Start is a no-op for the stub.
func (s *Server) Start() error {
	return nil
}

// Stop is a no-op for the stub.
func (s *Server) Stop(ctx context.Context) error {
	return nil
}

// AltSvcHeader returns empty string for the stub.
func (s *Server) AltSvcHeader() string {
	return ""
}

// IsRunning returns false for the stub.
func (s *Server) IsRunning() bool {
	return false
}

// GetConfig returns the server configuration.
func (s *Server) GetConfig() *Config {
	return s.config
}

// Stats holds HTTP/3 server statistics (stub).
type Stats struct {
	Connections    int64
	Requests       int64
	Errors         int64
	ZeroRTTUsed    int64
	MigrationCount int64
}

// GetStats returns empty stats for the stub.
func (s *Server) GetStats() Stats {
	return Stats{}
}

// EnableAltSvc is a passthrough for the stub.
func EnableAltSvc(next http.Handler, altSvcValue string) http.Handler {
	return next
}

// IsHTTP3Request always returns false for the stub.
func IsHTTP3Request(r *http.Request) bool {
	return false
}
