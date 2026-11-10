package cmd

import (
	"testing"

	"git.tatikoma.dev/corpix/deploy/internal/manifest"
)

func TestInstallerCapabilities(t *testing.T) {
	cases := []struct {
		m       manifest.Machine
		backend string
		valid   bool
	}{
		{manifest.Machine{Disko: true}, "nixos-anywhere", true},
		{manifest.Machine{}, "nixos-anywhere", false},
		{manifest.Machine{Installer: manifest.Installer{Attribute: "config.system.build.nandFlash"}}, "executable", true},
		{manifest.Machine{}, "executable", false},
		{manifest.Machine{}, "unsupported", false},
	}
	for _, c := range cases {
		if err := validateInstaller(c.m, c.backend); (err == nil) != c.valid {
			t.Errorf("%+v: %v", c, err)
		}
	}
}
