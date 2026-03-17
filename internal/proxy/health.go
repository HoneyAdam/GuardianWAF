package proxy

import (
	"fmt"
	"net/http"
	"sync"
	"time"
)

// HealthChecker periodically checks the health of all targets in a balancer.
type HealthChecker struct {
	balancer *Balancer
	interval time.Duration
	timeout  time.Duration
	path     string
	client   *http.Client
	stopCh   chan struct{}
	wg       sync.WaitGroup
}

// HealthConfig configures health checking.
type HealthConfig struct {
	Enabled  bool
	Interval time.Duration
	Timeout  time.Duration
	Path     string
}

// NewHealthChecker creates a new health checker for the given balancer.
func NewHealthChecker(b *Balancer, cfg HealthConfig) *HealthChecker {
	if cfg.Interval <= 0 {
		cfg.Interval = 10 * time.Second
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 3 * time.Second
	}
	if cfg.Path == "" {
		cfg.Path = "/"
	}

	return &HealthChecker{
		balancer: b,
		interval: cfg.Interval,
		timeout:  cfg.Timeout,
		path:     cfg.Path,
		client:   &http.Client{Timeout: cfg.Timeout},
		stopCh:   make(chan struct{}),
	}
}

// Start begins periodic health checking in a background goroutine.
func (hc *HealthChecker) Start() {
	hc.wg.Add(1)
	go func() {
		defer hc.wg.Done()

		// Initial check
		hc.checkAll()

		ticker := time.NewTicker(hc.interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				hc.checkAll()
			case <-hc.stopCh:
				return
			}
		}
	}()
}

// Stop stops the health checker and waits for it to finish.
func (hc *HealthChecker) Stop() {
	close(hc.stopCh)
	hc.wg.Wait()
}

// checkAll checks all targets in the balancer.
func (hc *HealthChecker) checkAll() {
	targets := hc.balancer.Targets()
	for _, t := range targets {
		healthy := hc.check(t)
		t.SetHealthy(healthy)
		t.lastCheck.Store(time.Now())
	}
}

// check performs a single health check against a target.
func (hc *HealthChecker) check(t *Target) bool {
	checkURL := fmt.Sprintf("%s://%s%s", t.URL.Scheme, t.URL.Host, hc.path)
	resp, err := hc.client.Get(checkURL)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode >= 200 && resp.StatusCode < 400
}
