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
	if got, want := f.Addresses["alexandria"].Default, "10.94.10.1"; got != want {
		t.Fatalf("Addresses[alexandria].Default = %q want %q", got, want)
	}
	if got, want := f.Addresses["ares"].Default, "200:dffb::1"; got != want {
		t.Fatalf("Addresses[ares].Default = %q want %q", got, want)
	}
	if len(f.Groups) != 0 {
		t.Fatalf("Groups: expected empty, got %v", f.Groups)
	}
}

func TestSaveAndLoadStructured(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "hosts")
	in := &File{
		Addresses: map[string]*AddressEntry{
			"pegasus": {Default: "10.94.10.3"},
		},
		Groups: map[string][]string{"dns": {"pegasus", "ares", "pegasus"}},
	}
	if err := Save(path, in); err != nil {
		t.Fatalf("Save: %v", err)
	}

	out, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got, want := out.Addresses["pegasus"].Default, "10.94.10.3"; got != want {
		t.Fatalf("Addresses[pegasus].Default = %q want %q", got, want)
	}
	if got, want := out.Groups["dns"], []string{"ares", "pegasus"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Groups[dns] = %v want %v", got, want)
	}
}

func TestTaggedAddressRoundTrip(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "hosts")
	in := &File{
		Addresses: map[string]*AddressEntry{
			"ares": {
				Default: "10.0.0.1",
				Tags:    map[string]string{"unlock": "5.6.7.8"},
			},
		},
	}
	if err := Save(path, in); err != nil {
		t.Fatalf("Save: %v", err)
	}

	out, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	entry := out.Addresses["ares"]
	if entry == nil {
		t.Fatal("Addresses[ares] is nil")
	}
	if got, want := entry.Default, "10.0.0.1"; got != want {
		t.Fatalf("Default = %q want %q", got, want)
	}
	if got, want := entry.Tags["unlock"], "5.6.7.8"; got != want {
		t.Fatalf("Tags[unlock] = %q want %q", got, want)
	}
}

func TestTaggedAddressFallback(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "hosts")
	if err := SetAddress(path, "zeus", "", "192.168.1.1"); err != nil {
		t.Fatalf("SetAddress default: %v", err)
	}

	addr, err := GetAddress(path, "zeus", "ssh")
	if err != nil {
		t.Fatalf("GetAddress ssh: %v", err)
	}
	if got, want := addr, "192.168.1.1"; got != want {
		t.Fatalf("GetAddress(ssh) = %q want %q (expected fallback to default)", got, want)
	}

	addr, err = GetAddress(path, "zeus", "unlock")
	if err != nil {
		t.Fatalf("GetAddress unlock: %v", err)
	}
	if got, want := addr, "192.168.1.1"; got != want {
		t.Fatalf("GetAddress(unlock) = %q want %q (expected fallback to default)", got, want)
	}
}

func TestTaggedAddressOverridesDefault(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "hosts")
	if err := SetAddress(path, "zeus", "", "10.0.0.1"); err != nil {
		t.Fatalf("SetAddress default: %v", err)
	}
	if err := SetAddress(path, "zeus", "unlock", "1.2.3.4"); err != nil {
		t.Fatalf("SetAddress unlock: %v", err)
	}

	ssh, err := GetAddress(path, "zeus", "ssh")
	if err != nil {
		t.Fatalf("GetAddress ssh: %v", err)
	}
	if got, want := ssh, "10.0.0.1"; got != want {
		t.Fatalf("GetAddress(ssh) = %q want %q", got, want)
	}

	unlock, err := GetAddress(path, "zeus", "unlock")
	if err != nil {
		t.Fatalf("GetAddress unlock: %v", err)
	}
	if got, want := unlock, "1.2.3.4"; got != want {
		t.Fatalf("GetAddress(unlock) = %q want %q", got, want)
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
