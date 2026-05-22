package state

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadMissingReportsZero(t *testing.T) {
	t.Parallel()

	got, err := Load(t.TempDir())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.Version != 0 {
		t.Fatalf("expected version 0 for missing state, got %d", got.Version)
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	t.Parallel()

	flakeDir := t.TempDir()
	if err := Save(flakeDir, &State{Version: 1}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := Load(flakeDir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.Version != 1 {
		t.Fatalf("expected version 1, got %d", got.Version)
	}
	data, err := os.ReadFile(filepath.Join(flakeDir, "vars", ".deploy.state"))
	if err != nil {
		t.Fatalf("read state file: %v", err)
	}
	if string(data) != "{\"version\":1}\n" {
		t.Fatalf("unexpected on-disk content %q", string(data))
	}
}
