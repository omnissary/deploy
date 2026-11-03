package atomicfile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func entries(t *testing.T, dir string) []string {
	t.Helper()
	es, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, len(es))
	for i, e := range es {
		names[i] = e.Name()
	}
	return names
}

func TestWriteCreatesAndReplaces(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "f")

	if err := Write(path, []byte("one"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Write(path, []byte("two"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "two" {
		t.Fatalf("content = %q, %v", got, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("mode = %o", info.Mode().Perm())
	}
	if names := entries(t, dir); len(names) != 1 {
		t.Fatalf("leftovers: %v", names)
	}
}

func TestWriteFailsForMissingDirectory(t *testing.T) {
	t.Parallel()
	if err := Write(filepath.Join(t.TempDir(), "missing", "f"), []byte("x"), 0o600); err == nil {
		t.Fatal("expected error")
	}
}

func TestWriteFailsWhenTargetIsDirectoryAndLeavesNoTemp(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	target := filepath.Join(dir, "d")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "inner"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Write(target, []byte("x"), 0o600); err == nil {
		t.Fatal("expected error replacing a non-empty directory")
	}
	if names := entries(t, dir); len(names) != 1 {
		t.Fatalf("leftovers: %v", names)
	}
}

func TestConcurrentWritesDoNotCollide(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "f")

	var wg sync.WaitGroup
	errs := make(chan error, 32)
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs <- Write(path, []byte(fmt.Sprintf("writer-%02d", i)), 0o600)
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent write failed: %v", err)
		}
	}
	got, err := os.ReadFile(path)
	if err != nil || len(got) != len("writer-00") {
		t.Fatalf("content = %q, %v", got, err)
	}
	if names := entries(t, dir); len(names) != 1 {
		t.Fatalf("leftovers: %v", names)
	}
}

func TestCreateWritesNewFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "f")

	if err := Create(path, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "data" {
		t.Fatalf("content = %q, %v", got, err)
	}
	if names := entries(t, dir); len(names) != 1 {
		t.Fatalf("leftovers: %v", names)
	}
}

func TestCreateRefusesExistingFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "f")
	if err := os.WriteFile(path, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}

	err := Create(path, []byte("new"), 0o600)
	if !errors.Is(err, os.ErrExist) {
		t.Fatalf("expected os.ErrExist, got %v", err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != "original" {
		t.Fatalf("content changed to %q", got)
	}
	if names := entries(t, dir); len(names) != 1 {
		t.Fatalf("leftovers: %v", names)
	}
}

func TestConcurrentCreateHasExactlyOneWinner(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "f")

	var wg sync.WaitGroup
	results := make(chan error, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results <- Create(path, []byte(fmt.Sprint(i)), 0o600)
		}(i)
	}
	wg.Wait()
	close(results)
	wins := 0
	for err := range results {
		switch {
		case err == nil:
			wins++
		case !errors.Is(err, os.ErrExist):
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if wins != 1 {
		t.Fatalf("%d creators succeeded, want 1", wins)
	}
}
