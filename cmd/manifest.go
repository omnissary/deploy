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
	if cfg.manifestInfo != nil {
		return cfg.manifestInfo()
	}
	raw, err := nix.EvalFlake(cfg.FlakeDir, manifest.Expression)
	if err != nil {
		return manifest.Manifest{}, err
	}
	return manifest.Decode(raw)
}
func machineMetadata(cfg *Config, name string) (manifest.Machine, error) {
	if _, err := requireMachineName(name); err != nil {
		return manifest.Machine{}, err
	}
	if cfg.machineInfo != nil {
		return cfg.machineInfo(name)
	}
	if cfg.manifestInfo != nil {
		m, err := cfg.manifestInfo()
		if err != nil {
			return manifest.Machine{}, err
		}
		v, ok := m.Machines[name]
		if !ok {
			return v, errors.Errorf("no deployment metadata for %s", name)
		}
		return v, nil
	}
	if value, ok := cfg.machineCache[name]; ok {
		return value, nil
	}
	encoded, _ := json.Marshal(name)
	expression := "flake: let m = (" + manifest.Expression + ") flake; in m // { machines = { " + string(encoded) + " = m.machines." + string(encoded) + "; }; }"
	raw, err := nix.EvalFlake(cfg.FlakeDir, expression)
	if err != nil {
		return manifest.Machine{}, err
	}
	m, err := manifest.Decode(raw)
	if err != nil {
		return manifest.Machine{}, err
	}
	v, ok := m.Machines[name]
	if !ok {
		return v, errors.Errorf("no deployment metadata for %s", name)
	}
	if cfg.machineCache == nil {
		cfg.machineCache = map[string]manifest.Machine{}
	}
	cfg.machineCache[name] = v
	return v, nil
}
func loadPolicyManifest(cfg *Config) (manifest.Manifest, error) {
	if cfg.manifestInfo != nil {
		return cfg.manifestInfo()
	}
	if cfg.policyCache != nil {
		return *cfg.policyCache, nil
	}
	raw, err := nix.EvalFlake(cfg.FlakeDir, "flake: let m = ("+manifest.Expression+") flake; in m // { machines = {}; }")
	if err != nil {
		return manifest.Manifest{}, err
	}
	m, err := manifest.Decode(raw)
	if err == nil {
		cfg.policyCache = &m
	}
	return m, err
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
