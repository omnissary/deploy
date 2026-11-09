package cmd

import (
	"encoding/json"
	"fmt"

	"git.tatikoma.dev/corpix/atlas/errors"
	"git.tatikoma.dev/corpix/deploy/internal/manifest"
	"git.tatikoma.dev/corpix/deploy/internal/nix"
	"github.com/urfave/cli/v2"
)

// Evaluate public metadata once. The fallback does not depend on key-file existence.
func loadManifest(cfg *Config) (manifest.Manifest, error) {
	raw, err := nix.EvalApply(cfg.FlakeDir, "", manifest.Expression)
	if err != nil {
		return manifest.Manifest{}, err
	}
	return manifest.Decode(raw)
}
func machineMetadata(cfg *Config, name string) (manifest.Machine, error) {
	if cfg.machineInfo != nil {
		return cfg.machineInfo(name)
	}
	m, err := loadManifest(cfg)
	if err != nil {
		return manifest.Machine{}, err
	}
	v, ok := m.Machines[name]
	if !ok {
		return v, errors.Errorf("no deployment metadata for machine %s", name)
	}
	return v, nil
}
func machineInspectCmd() *cli.Command {
	return &cli.Command{Name: "inspect", Usage: "show resolved machine capabilities and supported operations", ArgsUsage: "<machine>", Flags: []cli.Flag{&cli.BoolFlag{Name: "json"}}, Action: func(ctx *cli.Context) error {
		if ctx.NArg() != 1 {
			return errors.New("usage: machine inspect <machine>")
		}
		v, err := machineMetadata(getConfig(ctx), ctx.Args().First())
		if err != nil {
			return err
		}
		if ctx.Bool("json") {
			return json.NewEncoder(ctx.App.Writer).Encode(v)
		}
		fmt.Fprintf(ctx.App.Writer, "system: %s\ninstaller: %s\nhost key: %t\nmanaged initrd SSH: %t (port %d)\nunlock: %s\nsource: %s\n", v.System, v.Installer.Backend, v.HostKey, v.InitrdSSH, v.InitrdPort, v.Unlock, v.Source)
		return nil
	}}
}
