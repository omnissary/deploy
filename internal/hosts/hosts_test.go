package hosts

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestLoadAcceptsLegacyFlatFormat(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "hosts")
	raw := []byte("alexandria: 10.94.10.1\nares: 200:dffb::1\n")
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatalf("write hosts: %v", err)
	}

	f, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := map[string]string{"alexandria": "10.94.10.1", "ares": "200:dffb::1"}
	if !reflect.DeepEqual(f.Addresses, want) {
		t.Fatalf("Addresses: got %v want %v", f.Addresses, want)
	}
	if len(f.Groups) != 0 {
		t.Fatalf("Groups: expected empty, got %v", f.Groups)
	}
}

func TestSaveAndLoadStructured(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "hosts")
	in := &File{
		Addresses: map[string]string{"pegasus": "10.94.10.3"},
		Groups:    map[string][]string{"dns": {"pegasus", "ares", "pegasus"}},
	}
	if err := Save(path, in); err != nil {
		t.Fatalf("Save: %v", err)
	}

	out, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got, want := out.Addresses["pegasus"], "10.94.10.3"; got != want {
		t.Fatalf("Addresses[pegasus] = %q want %q", got, want)
	}
	if got, want := out.Groups["dns"], []string{"ares", "pegasus"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Groups[dns] = %v want %v", got, want)
	}
}

func TestAddAndRemoveMembers(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "hosts")
	if err := CreateGroup(path, "dns", []string{"pegasus"}); err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	if _, err := AddMembers(path, "dns", []string{"ares", "athena"}); err != nil {
		t.Fatalf("AddMembers: %v", err)
	}
	members, err := GroupMembers(path, "dns")
	if err != nil {
		t.Fatalf("GroupMembers: %v", err)
	}
	if got, want := members, []string{"ares", "athena", "pegasus"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("members after add = %v want %v", got, want)
	}

	if _, err := RemoveMembers(path, "dns", []string{"pegasus"}); err != nil {
		t.Fatalf("RemoveMembers: %v", err)
	}
	members, err = GroupMembers(path, "dns")
	if err != nil {
		t.Fatalf("GroupMembers: %v", err)
	}
	if got, want := members, []string{"ares", "athena"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("members after remove = %v want %v", got, want)
	}
}

func TestCreateGroupRejectsDuplicate(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "hosts")
	if err := CreateGroup(path, "dns", nil); err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	if err := CreateGroup(path, "dns", nil); err == nil {
		t.Fatal("expected duplicate CreateGroup to fail")
	}
}
