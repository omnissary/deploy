package vars

import "testing"

func TestValidName(t *testing.T) {
	t.Parallel()
	for name, want := range map[string]bool{
		"web":      true,
		"web-1":    true,
		"web_1":    true,
		"0db":      true,
		"":         false,
		"-web":     false,
		"_web":     false,
		"Web":      false,
		"web.1":    false,
		"web/1":    false,
		"../web":   false,
		"web*":     false,
		"web name": false,
		"web\n":    false,
	} {
		if got := ValidName(name); got != want {
			t.Errorf("ValidName(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestMachineFromHostKeyPubPath(t *testing.T) {
	t.Parallel()
	if got := MachineFromHostKeyPubPath(MachineHostKeyPubPath("/flake", "web-1")); got != "web-1" {
		t.Fatalf("got %q", got)
	}
}
