package repolock

import "testing"

func TestExclusive(t *testing.T) {
	root := t.TempDir()
	release, err := Acquire(root)
	if err != nil {
		t.Fatal(err)
	}
	if r, err := Acquire(root); err == nil {
		r()
		t.Fatal("concurrent lock accepted")
	}
	release()
	r, err := Acquire(root)
	if err != nil {
		t.Fatal(err)
	}
	r()
}
