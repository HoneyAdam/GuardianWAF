package guardianwaf

import (
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/config"
)

func TestWithDetector_NilMapDirect(t *testing.T) {
	cfg := &config.Config{}
	WithDetector("sqli", true, 2.0)(cfg)
	if cfg.WAF.Detection.Detectors == nil {
		t.Fatal("expected detectors map to be initialized")
	}
}

func TestNew_WithDetectionExclusions(t *testing.T) {
	eng, err := New(Config{
		Detection: DetectionConfig{
			SQLi: DetectorConfig{Enabled: true, Multiplier: 1.0},
			Exclusions: []ExclusionConfig{
				{Path: "/health", Detectors: []string{"sqli"}, Reason: "health check"},
			},
		},
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer eng.Close()
}
