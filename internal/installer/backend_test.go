package installer

import (
	"testing"

	"git.tatikoma.dev/corpix/deploy/internal/manifest"
)

func TestBackendSeam(t *testing.T) {
	r := NewRegistry()
	r["another-board"] = Executable{}
	b, err := r.Resolve("another-board")
	if err != nil {
		t.Fatal(err)
	}
	m := manifest.Machine{Installer: manifest.Installer{Attribute: "config.system.build.nandFlash"}}
	if err := b.Validate(m); err != nil {
		t.Fatal(err)
	}
	if b.SecretDelivery() != "out-of-band" || b.Artifacts(m)[0] != m.Installer.Attribute {
		t.Fatal("board requires native encrypted storage")
	}
	command, err := b.Command(Prepared{Artifact: "/nix/store/example-flasher"})
	if err != nil || command.Program != "/nix/store/example-flasher" {
		t.Fatal(err)
	}
	if _, err := b.Command(Prepared{}); err == nil {
		t.Fatal("unbuilt installer accepted")
	}
}
