package cmd

import (
	"fmt"
	"git.tatikoma.dev/corpix/atlas/errors"
	"git.tatikoma.dev/corpix/deploy/internal/manifest"
	"git.tatikoma.dev/corpix/deploy/internal/nix"
	"github.com/urfave/cli/v2"
	"os"
	"os/exec"
	"strings"
)

// validateInstaller is the installation seam: filesystem and CPU do not select transport.
func validateInstaller(meta manifest.Machine, backend string) error {
	switch backend {
	case "nixos-anywhere":
		if !meta.Disko {
			return errors.New("nixos-anywhere requires a declared diskoScript")
		}
	case "executable":
		if !strings.HasPrefix(meta.Installer.Attribute, "config.system.build.") {
			return errors.New("executable installer requires a config.system.build artifact")
		}
	default:
		return errors.Errorf("unsupported installation backend %q; build/deploy remain available", backend)
	}
	return nil
}
func buildInstallArtifacts(ctx *cli.Context, cfg *Config, machine string, meta manifest.Machine) error {
	attrs := []string{"config.system.build.toplevel"}
	if meta.Installer.Backend == "executable" {
		attrs = []string{meta.Installer.Attribute}
	} else if meta.Disko {
		attrs = append(attrs, "config.system.build.diskoScript")
	}
	for _, attr := range attrs {
		path, err := nix.Build(cfg.FlakeDir, cfg.MachineAttr(machine, attr))
		if err != nil {
			return err
		}
		fmt.Fprintln(ctx.App.Writer, path)
	}
	return nil
}
func executableInstall(ctx *cli.Context, cfg *Config, machine string, meta manifest.Machine) error {
	for _, flag := range []string{"kexec", "kexec-flavor", "phases", "ssh-option", "port"} {
		if ctx.IsSet(flag) {
			return errors.Errorf("--%s is not supported by executable installers", flag)
		}
	}
	if err := provisionMachine(cfg, machine); err != nil {
		return err
	}
	artifact, err := nix.Build(cfg.FlakeDir, cfg.MachineAttr(machine, meta.Installer.Attribute))
	if err != nil {
		return err
	}
	command := exec.Command(artifact)
	command.Stdin = os.Stdin
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	if err := command.Run(); err != nil {
		return errors.Wrap(err, "run declared installer (USB access may require running the installer directly with appropriate privileges)")
	}
	fmt.Fprintln(ctx.App.Writer, "flashed-needs-configuration: boot the device and deploy over its existing USB/network address; no decrypted secrets were embedded in the image")
	return nil
}
