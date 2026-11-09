package cmd

import (
	"fmt"
	"git.tatikoma.dev/corpix/atlas/errors"
	"git.tatikoma.dev/corpix/deploy/internal/installer"
	"git.tatikoma.dev/corpix/deploy/internal/manifest"
	"git.tatikoma.dev/corpix/deploy/internal/nix"
	"github.com/urfave/cli/v2"
	"os"
	"os/exec"
	"strings"
)

// validateInstaller is the installation seam: filesystem and CPU do not select transport.
var installationBackends = installer.NewRegistry()

func validateInstaller(meta manifest.Machine, backend string) error {
	handler, err := installationBackends.Resolve(backend)
	if err != nil {
		return err
	}
	return handler.Validate(meta)
}
func buildInstallArtifacts(ctx *cli.Context, cfg *Config, machine string, meta manifest.Machine) error {
	handler, err := installationBackends.Resolve(meta.Installer.Backend)
	if err != nil {
		return err
	}
	attrs := handler.Artifacts(meta)
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
	handler, err := installationBackends.Resolve(meta.Installer.Backend)
	if err != nil {
		return err
	}
	invocation, err := handler.Command(installer.Prepared{Artifact: artifact})
	if err != nil {
		return err
	}
	command := exec.CommandContext(ctx.Context, invocation.Program, invocation.Arguments...)
	command.Stdin = os.Stdin
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	if err := command.Run(); err != nil {
		return errors.Wrap(err, "run declared installer (USB access may require running the installer directly with appropriate privileges)")
	}
	fmt.Fprintln(ctx.App.Writer, "flashed-needs-configuration: boot the device and deploy over its existing USB/network address; no decrypted secrets were embedded in the image")
	return nil
}

func shellArg(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'" }
