package testreliability

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRecorderFlush(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "results.jsonl")

	rec := NewRecorder(path)
	rec.Record("TestA", true, 10000000)
	rec.Record("TestB", false, 20000000)
	rec.Record("TestA", false, 5000000) // second run, now fails

	if err := rec.Flush(); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Error("file should not be empty")
	}
}

func TestDetectFlaky(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "flaky.jsonl")

	rec := NewRecorder(path)
	// Run 1: TestA passes, TestB passes
	rec.Record("TestA", true, 10000000)
	rec.Record("TestB", true, 10000000)
	rec.Flush()

	// Run 2: TestA fails (flaky!), TestB passes
	rec2 := NewRecorder(path)
	rec2.Record("TestA", false, 10000000)
	rec2.Record("TestB", true, 10000000)
	rec2.Flush()

	flaky := DetectFlaky(path)
	if len(flaky) != 1 {
		t.Fatalf("expected 1 flaky test, got %d: %v", len(flaky), flaky)
	}
	if flaky[0] != "TestA" {
		t.Errorf("expected TestA to be flaky, got %q", flaky[0])
	}
}

func TestDetectFlaky_NoFlaky(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "stable.jsonl")

	rec := NewRecorder(path)
	rec.Record("TestA", true, 10000000)
	rec.Record("TestB", true, 10000000)
	rec.Flush()

	rec2 := NewRecorder(path)
	rec2.Record("TestA", true, 10000000)
	rec2.Record("TestB", true, 10000000)
	rec2.Flush()

	flaky := DetectFlaky(path)
	if len(flaky) != 0 {
		t.Errorf("expected no flaky tests, got %v", flaky)
	}
}

func TestDetectFlaky_EmptyFile(t *testing.T) {
	flaky := DetectFlaky("/nonexistent/path.jsonl")
	if len(flaky) != 0 {
		t.Error("should return empty for missing file")
	}
}
