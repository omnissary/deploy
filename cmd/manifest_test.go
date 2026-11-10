package cmd

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"git.tatikoma.dev/corpix/deploy/internal/manifest"
)

func TestMetadataExpression(t *testing.T) {
	expression := manifest.Expression
	file := filepath.Join(t.TempDir(), "metadata.nix")
	os.WriteFile(file, []byte(expression), 0o600)
	if _, err := exec.LookPath("nix-instantiate"); err != nil {
		t.Skip("nix unavailable")
	}
	expr := "let f = import " + file + `; in f {
 nixosConfigurations.broken = throw "machine configuration must not be inspected";
 deploy = { schemaVersion = 2; machines = {
  board = { system = "armv7l-linux"; installer = { backend="executable"; attribute="config.system.build.nandFlash"; }; };
  zfs = { system="x86_64-linux"; hostKey=true; initrdSSH=true; };
  luks = { system="aarch64-linux"; initrdSSH=true; unlock="luks"; };
 }; }; }`
	out, err := exec.Command("nix-instantiate", "--eval", "--strict", "--json", "--expr", expr).CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	var m manifest.Manifest
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatal(err)
	}
	if m.Machines["board"].InitrdSSH || m.Machines["board"].Installer.Backend != "executable" {
		t.Fatal(m)
	}
	if !m.Machines["zfs"].InitrdSSH {
		t.Fatal("bootstrap must enable keys before files exist")
	}
	if m.Machines["luks"].Unlock != "luks" {
		t.Fatal(m)
	}
}

func TestLoadMetadataWithoutDefaultPackage(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	if _, err := exec.LookPath("nix"); err != nil {
		t.Skip("nix unavailable")
	}
	root := t.TempDir()
	writeFlake(t, root, `{ outputs = _: { deploy = { schemaVersion=2; machines.board={system="armv7l-linux";installer={backend="executable";attribute="config.system.build.nandFlash";};}; }; }; }`)
	m, err := loadManifest(&Config{FlakeDir: root})
	if err != nil {
		t.Fatal(err)
	}
	if m.Machines["board"].System != "armv7l-linux" || m.Machines["board"].Installer.Backend != "executable" {
		t.Fatal(m)
	}
}

func TestSelectedMachineDoesNotEvaluateUnrelatedBrokenConfiguration(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	if _, err := exec.LookPath("nix"); err != nil {
		t.Skip("nix unavailable")
	}
	root := t.TempDir()
	writeFlake(t, root, `{ outputs = _: {
 nixosConfigurations.broken=throw "unrelated machine must not evaluate";
 deploy={schemaVersion=2; authorities=throw "unrelated authority must not evaluate"; certificates=throw "unrelated certificate must not evaluate"; trust=throw "unrelated trust must not evaluate"; machines={broken=throw "unrelated policy must not evaluate";board={system="armv7l-linux";};};};
 }; }`)
	m, err := machineMetadata(&Config{FlakeDir: root}, "board")
	if err != nil || m.System != "armv7l-linux" {
		t.Fatal(m, err)
	}
}
