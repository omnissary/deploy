package cmd

import (
	"encoding/json"
	"git.tatikoma.dev/corpix/deploy/internal/manifest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestMetadataExpression(t *testing.T) {
	expression := manifest.Expression
	file := filepath.Join(t.TempDir(), "metadata.nix")
	os.WriteFile(file, []byte(expression), 0600)
	if _, err := exec.LookPath("nix-instantiate"); err != nil {
		t.Skip("nix unavailable")
	}
	expr := "let f = import " + file + `; in f { nixosConfigurations = {
 chip.config = { system.build.nandFlash = "unused"; hardware.allwinner.chip.storage="nand"; boot.initrd.network.ssh.enable=false; nixpkgs.hostPlatform.system="armv7l-linux"; };
 zfs.config = { system.build.diskoScript="unused"; modules.initrd-networking.enable=true; boot.initrd.network.ssh.enable=true; boot.loader.supportsInitrdSecrets=true; modules.zfs-crypt={enable=true;pools.rpool={keyPath="/run/zfs-keys/rpool.key";};}; };
 luks.config = { system.build={}; modules.cryptsetup.askPassword=true; };
 }; }`
	out, err := exec.Command("nix-instantiate", "--eval", "--strict", "--json", "--expr", expr).CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	var m manifest.Manifest
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatal(err)
	}
	if m.Machines["chip"].InitrdSSH || m.Machines["chip"].Installer.Backend != "executable" {
		t.Fatal(m)
	}
	if !m.Machines["zfs"].InitrdSSH {
		t.Fatal("bootstrap must enable keys before files exist")
	}
	if m.Machines["luks"].Unlock != "luks" {
		t.Fatal(m)
	}
}
