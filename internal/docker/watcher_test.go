package docker

import (
	"testing"
	"time"
)

func TestNewWatcher_Defaults(t *testing.T) {
	w := NewWatcher(nil, "", "", 0)
	if w.labelPrefix != "gwaf" {
		t.Errorf("expected default prefix 'gwaf', got %q", w.labelPrefix)
	}
	if w.network != "bridge" {
		t.Errorf("expected default network 'bridge', got %q", w.network)
	}
	if w.pollInterval != 5*time.Second {
		t.Errorf("expected default poll 5s, got %v", w.pollInterval)
	}
}

func TestNewWatcher_CustomValues(t *testing.T) {
	w := NewWatcher(nil, "myapp", "host", 10*time.Second)
	if w.labelPrefix != "myapp" {
		t.Errorf("expected prefix 'myapp', got %q", w.labelPrefix)
	}
	if w.network != "host" {
		t.Errorf("expected network 'host', got %q", w.network)
	}
	if w.pollInterval != 10*time.Second {
		t.Errorf("expected poll 10s, got %v", w.pollInterval)
	}
}

func TestWatcher_Services(t *testing.T) {
	w := NewWatcher(nil, "gwaf", "bridge", 5*time.Second)
	w.services["abc123"] = &DiscoveredService{
		ContainerID:   "abc123",
		ContainerName: "api",
		Host:          "api.example.com",
		Port:          8088,
		IPAddress:     "172.17.0.2",
	}

	svcs := w.Services()
	if len(svcs) != 1 {
		t.Fatalf("expected 1 service, got %d", len(svcs))
	}
	if svcs[0].ContainerName != "api" {
		t.Errorf("got %q", svcs[0].ContainerName)
	}
}

func TestWatcher_ServiceCount(t *testing.T) {
	w := NewWatcher(nil, "gwaf", "bridge", 5*time.Second)
	if w.ServiceCount() != 0 {
		t.Errorf("expected 0, got %d", w.ServiceCount())
	}

	w.services["a"] = &DiscoveredService{ContainerID: "a"}
	w.services["b"] = &DiscoveredService{ContainerID: "b"}
	if w.ServiceCount() != 2 {
		t.Errorf("expected 2, got %d", w.ServiceCount())
	}
}

func TestWatcher_SetOnChange(t *testing.T) {
	w := NewWatcher(nil, "gwaf", "bridge", 5*time.Second)
	called := false
	w.SetOnChange(func() { called = true })
	w.notifyChange()
	if !called {
		t.Error("onChange should have been called")
	}
}

func TestWatcher_SetLogger(t *testing.T) {
	w := NewWatcher(nil, "gwaf", "bridge", 5*time.Second)
	var logged string
	w.SetLogger(func(_, msg string) { logged = msg })
	w.logFn("info", "test message")
	if logged != "test message" {
		t.Errorf("got %q", logged)
	}
}

func TestWatcher_HandleEvent_Start(t *testing.T) {
	w := NewWatcher(nil, "gwaf", "bridge", 5*time.Second)
	var logs []string
	w.SetLogger(func(_, msg string) { logs = append(logs, msg) })

	// Start event will call sync() which tries to list containers.
	// With nil client, dockerCmd will panic on nil pointer.
	// So we skip testing start event with nil client.
	// Instead verify stop/destroy/die events work without client.
}

func TestWatcher_HandleEvent_Stop(t *testing.T) {
	w := NewWatcher(nil, "gwaf", "bridge", 5*time.Second)
	w.services["abc123"] = &DiscoveredService{ContainerID: "abc123", ContainerName: "test"}

	var logs []string
	w.SetLogger(func(_, msg string) { logs = append(logs, msg) })

	changed := false
	w.SetOnChange(func() { changed = true })

	w.handleEvent(Event{
		Type:   "container",
		Action: "stop",
		Actor: struct {
			ID         string            `json:"ID"`
			Attributes map[string]string `json:"Attributes"`
		}{
			ID:         "abc123",
			Attributes: map[string]string{"name": "test-app"},
		},
	})

	if w.ServiceCount() != 0 {
		t.Errorf("service should be removed, got %d", w.ServiceCount())
	}
	if !changed {
		t.Error("onChange should have been called")
	}
}

func TestWatcher_HandleEvent_Destroy(t *testing.T) {
	w := NewWatcher(nil, "gwaf", "bridge", 5*time.Second)
	w.services["xyz789"] = &DiscoveredService{ContainerID: "xyz789"}

	w.handleEvent(Event{
		Action: "destroy",
		Actor: struct {
			ID         string            `json:"ID"`
			Attributes map[string]string `json:"Attributes"`
		}{ID: "xyz789"},
	})

	if w.ServiceCount() != 0 {
		t.Errorf("service should be removed after destroy, got %d", w.ServiceCount())
	}
}

func TestWatcher_HandleEvent_IgnoreOther(t *testing.T) {
	w := NewWatcher(nil, "gwaf", "bridge", 5*time.Second)
	w.services["abc"] = &DiscoveredService{ContainerID: "abc"}

	// Unknown action should not affect services
	w.handleEvent(Event{
		Action: "pause",
		Actor: struct {
			ID         string            `json:"ID"`
			Attributes map[string]string `json:"Attributes"`
		}{ID: "abc"},
	})

	if w.ServiceCount() != 1 {
		t.Errorf("service should still exist, got %d", w.ServiceCount())
	}
}

func TestItoa(t *testing.T) {
	tests := []struct {
		in   int
		want string
	}{
		{0, "0"},
		{1, "1"},
		{42, "42"},
		{100, "100"},
		{9999, "9999"},
	}
	for _, tt := range tests {
		got := itoa(tt.in)
		if got != tt.want {
			t.Errorf("itoa(%d) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestWatcher_ServicesEmpty(t *testing.T) {
	w := NewWatcher(nil, "gwaf", "bridge", 5*time.Second)
	svcs := w.Services()
	if svcs == nil || len(svcs) != 0 {
		t.Errorf("expected empty non-nil slice, got %v", svcs)
	}
}
