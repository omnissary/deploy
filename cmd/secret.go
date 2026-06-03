package cmd

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"git.tatikoma.dev/corpix/atlas/errors"
	"git.tatikoma.dev/corpix/atlas/log"
	"github.com/urfave/cli/v2"

	"git.tatikoma.dev/corpix/deploy/internal/hosts"
	"git.tatikoma.dev/corpix/deploy/internal/sops"
	"git.tatikoma.dev/corpix/deploy/internal/vars"
)

// secretTarget is the resolved target of a secret operation.
type secretTarget struct {
	name string
	path string
	kind targetKind
}

type targetKind int

const (
	targetMachine targetKind = iota
	targetGroup
)

// Argument positions for secret subcommand BashComplete functions.
// ctx.NArg() equals the number of positional args already on the command line,
// which is the 0-based index of the argument currently being completed.
const (
	secretArgTarget    = 0
	secretArgKey       = 1
	secretArgDstTarget = 2
	secretArgDstKey    = 3
)

func secretValueFromInput(raw []byte) string {
	return string(raw)
}

func writeSecretValue(w io.Writer, value string) error {
	_, err := io.WriteString(w, value)
	return err
}

func secretCmd() *cli.Command {
	return &cli.Command{
		Name:  "secret",
		Usage: "manage SOPS-encrypted secret files for machines and groups",
		Before: func(ctx *cli.Context) error {
			cfg := getConfig(ctx)
			if err := requireFlake(cfg); err != nil {
				return err
			}
			return requireAdminSOPSConfig(cfg)
		},
		Subcommands: []*cli.Command{
			{
				Name:      "list",
				Usage:     "list top-level secret keys; with no name, list every secret file",
				ArgsUsage: "[<name>]",
				BashComplete: func(ctx *cli.Context) {
					if ctx.NArg() > secretArgTarget {
						return
					}
					cfg := completionConfig(ctx)
					for _, name := range completionExistingTargetNames(cfg) {
						fmt.Fprintln(ctx.App.Writer, name)
					}
				},
				Action: func(ctx *cli.Context) error {
					cfg := getConfig(ctx)
					if ctx.NArg() == 0 {
						return listAllSecrets(cfg)
					}
					target, err := resolveSecretTarget(cfg, ctx.Args().Get(0))
					if err != nil {
						return err
					}
					if !fileExists(target.path) {
						return errors.Errorf("no secrets file at %s", target.path)
					}
					return listSecretFileKeys(target.path, target.name)
				},
			},
			{
				Name:      "get",
				Usage:     "decrypt and print the value of a secret key",
				ArgsUsage: "<name> <key>",
				BashComplete: func(ctx *cli.Context) {
					cfg := completionConfig(ctx)
					switch ctx.NArg() {
					case secretArgTarget:
						for _, name := range completionTargetNames(cfg) {
							fmt.Fprintln(ctx.App.Writer, name)
						}
					case secretArgKey:
						for _, key := range completionTargetKeys(cfg, ctx.Args().Get(secretArgTarget)) {
							fmt.Fprintln(ctx.App.Writer, key)
						}
					}
				},
				Action: func(ctx *cli.Context) error {
					if ctx.NArg() < 2 {
						return errors.New("usage: secret get <name> <key>")
					}
					cfg := getConfig(ctx)
					target, err := resolveSecretTarget(cfg, ctx.Args().Get(0))
					if err != nil {
						return err
					}
					key := ctx.Args().Get(1)
					if !fileExists(target.path) {
						return errors.Errorf("no secrets file at %s", target.path)
					}
					log.Debug().Str("target", target.name).Str("key", key).Msg("secret get")
					val, err := sops.DecryptYAMLExtract(target.path, key)
					if err != nil {
						return errors.Wrapf(err, "get secret %s/%s", target.name, key)
					}
					return writeSecretValue(os.Stdout, val)
				},
			},
			{
				Name:      "set",
				Usage:     "read value from stdin and write it as a secret key; creates the file on first use",
				ArgsUsage: "<name> <key>",
				BashComplete: func(ctx *cli.Context) {
					cfg := completionConfig(ctx)
					switch ctx.NArg() {
					case secretArgTarget:
						for _, name := range completionTargetNames(cfg) {
							fmt.Fprintln(ctx.App.Writer, name)
						}
					case secretArgKey:
						for _, key := range completionTargetKeys(cfg, ctx.Args().Get(secretArgTarget)) {
							fmt.Fprintln(ctx.App.Writer, key)
						}
					}
				},
				Action: func(ctx *cli.Context) error {
					if ctx.NArg() < 2 {
						return errors.New("usage: secret set <name> <key>")
					}
					cfg := getConfig(ctx)
					target, err := resolveSecretTarget(cfg, ctx.Args().Get(0))
					if err != nil {
						return err
					}
					if err := ensureSecretFile(cfg, target); err != nil {
						return err
					}
					key := ctx.Args().Get(1)
					log.Debug().Str("target", target.name).Str("key", key).Msg("secret set")
					raw, err := io.ReadAll(os.Stdin)
					if err != nil {
						return errors.Wrap(err, "read stdin")
					}
					if err := sops.SetYAML(target.path, key, secretValueFromInput(raw)); err != nil {
						return errors.Wrapf(err, "set secret %s/%s", target.name, key)
					}
					log.Info().Str("target", target.name).Str("key", key).Msg("secret set")
					return nil
				},
			},
			{
				Name:      "del",
				Usage:     "delete a secret key",
				ArgsUsage: "<name> <key>",
				BashComplete: func(ctx *cli.Context) {
					cfg := completionConfig(ctx)
					switch ctx.NArg() {
					case secretArgTarget:
						for _, name := range completionExistingTargetNames(cfg) {
							fmt.Fprintln(ctx.App.Writer, name)
						}
					case secretArgKey:
						for _, key := range completionTargetKeys(cfg, ctx.Args().Get(secretArgTarget)) {
							fmt.Fprintln(ctx.App.Writer, key)
						}
					}
				},
				Action: func(ctx *cli.Context) error {
					if ctx.NArg() < 2 {
						return errors.New("usage: secret del <name> <key>")
					}
					cfg := getConfig(ctx)
					target, err := resolveSecretTarget(cfg, ctx.Args().Get(0))
					if err != nil {
						return err
					}
					key := ctx.Args().Get(1)
					if !fileExists(target.path) {
						return errors.Errorf("no secrets file at %s", target.path)
					}
					log.Debug().Str("target", target.name).Str("key", key).Msg("secret del")
					if err := sops.DeleteYAML(target.path, key); err != nil {
						return errors.Wrapf(err, "del secret %s/%s", target.name, key)
					}
					log.Info().Str("target", target.name).Str("key", key).Msg("secret deleted")
					return nil
				},
			},
			{
				Name:      "update",
				Usage:     "re-encrypt secrets with current keys from .sops.yaml; with no name, update every file",
				ArgsUsage: "[<name>]",
				BashComplete: func(ctx *cli.Context) {
					if ctx.NArg() > secretArgTarget {
						return
					}
					cfg := completionConfig(ctx)
					for _, name := range completionExistingTargetNames(cfg) {
						fmt.Fprintln(ctx.App.Writer, name)
					}
				},
				Action: func(ctx *cli.Context) error {
					cfg := getConfig(ctx)
					if ctx.NArg() == 0 {
						return updateAllSecrets(cfg)
					}
					target, err := resolveSecretTarget(cfg, ctx.Args().Get(0))
					if err != nil {
						return err
					}
					if !fileExists(target.path) {
						return errors.Errorf("no secrets file at %s", target.path)
					}
					log.Info().Str("file", target.path).Msg("updating secret keys")
					if err := sops.UpdateKeys(cfg.SopsConf, target.path); err != nil {
						return errors.Wrapf(err, "update keys for %s", target.name)
					}
					return nil
				},
			},
			{
				Name:      "mv",
				Usage:     "move a secret key from one target to another, or rename it within the same target",
				ArgsUsage: "<src-name> <src-key> <dst-name> [<dst-key>]",
				BashComplete: func(ctx *cli.Context) {
					cfg := completionConfig(ctx)
					switch ctx.NArg() {
					case secretArgTarget:
						for _, name := range completionTargetNames(cfg) {
							fmt.Fprintln(ctx.App.Writer, name)
						}
					case secretArgKey:
						for _, key := range completionTargetKeys(cfg, ctx.Args().Get(secretArgTarget)) {
							fmt.Fprintln(ctx.App.Writer, key)
						}
					case secretArgDstTarget:
						for _, name := range completionTargetNames(cfg) {
							fmt.Fprintln(ctx.App.Writer, name)
						}
					case secretArgDstKey:
						for _, key := range completionTargetKeys(cfg, ctx.Args().Get(secretArgDstTarget)) {
							fmt.Fprintln(ctx.App.Writer, key)
						}
					}
				},
				Action: func(ctx *cli.Context) error {
					if ctx.NArg() < 3 {
						return errors.New("usage: secret mv <src-name> <src-key> <dst-name> [<dst-key>]")
					}
					cfg := getConfig(ctx)
					src, err := resolveSecretTarget(cfg, ctx.Args().Get(0))
					if err != nil {
						return err
					}
					srcKey := ctx.Args().Get(1)
					dst, err := resolveSecretTarget(cfg, ctx.Args().Get(2))
					if err != nil {
						return err
					}
					dstKey := srcKey
					if ctx.NArg() >= 4 {
						dstKey = ctx.Args().Get(3)
					}
					if src.path == dst.path && srcKey == dstKey {
						return errors.New("source and destination are identical")
					}
					if !fileExists(src.path) {
						return errors.Errorf("no secrets file at %s", src.path)
					}
					log.Debug().
						Str("src", src.name).Str("src-key", srcKey).
						Str("dst", dst.name).Str("dst-key", dstKey).
						Msg("secret mv")
					val, err := sops.DecryptYAMLExtract(src.path, srcKey)
					if err != nil {
						return errors.Wrapf(err, "read secret %s/%s", src.name, srcKey)
					}
					if err := ensureSecretFile(cfg, dst); err != nil {
						return err
					}
					if err := sops.SetYAML(dst.path, dstKey, val); err != nil {
						return errors.Wrapf(err, "write secret %s/%s", dst.name, dstKey)
					}
					if err := sops.DeleteYAML(src.path, srcKey); err != nil {
						return errors.Wrapf(err, "delete secret %s/%s", src.name, srcKey)
					}
					log.Info().
						Str("src", src.name).Str("src-key", srcKey).
						Str("dst", dst.name).Str("dst-key", dstKey).
						Msg("secret moved")
					return nil
				},
			},
			{
				Name:      "verify",
				Usage:     "verify secret integrity/decryption for a target or all encrypted files",
				ArgsUsage: "[<name>]",
				BashComplete: func(ctx *cli.Context) {
					if ctx.NArg() > secretArgTarget {
						return
					}
					cfg := completionConfig(ctx)
					for _, name := range completionExistingTargetNames(cfg) {
						fmt.Fprintln(ctx.App.Writer, name)
					}
				},
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:  "fix",
						Usage: "attempt to repair a broken secret file by re-encrypting it with the current .sops.yaml recipients",
					},
				},
				Action: func(ctx *cli.Context) error {
					cfg := getConfig(ctx)
					if ctx.NArg() < 1 {
						return verifyAllSecrets(cfg, ctx.Bool("fix"))
					}
					target, err := resolveSecretTarget(cfg, ctx.Args().Get(0))
					if err != nil {
						return err
					}
					if !fileExists(target.path) {
						return errors.Errorf("no secrets file at %s", target.path)
					}
					return verifySecretFile(cfg, target.path, ctx.Bool("fix"))
				},
			},
		},
	}
}

// resolveSecretTarget interprets name as either a group declared in the hosts
// file (resolves to the shared secrets file) or a machine declared in the
// flake (resolves to the per-machine secrets file). Groups win when a name
// could match both, but 'group create' rejects collisions to keep the
// namespace clean.
func resolveSecretTarget(cfg *Config, raw string) (*secretTarget, error) {
	name, err := requireSimpleName("name", raw)
	if err != nil {
		return nil, err
	}
	isGroup, err := hosts.HasGroup(cfg.HostsFile, name)
	if err != nil {
		return nil, err
	}
	if isGroup {
		return &secretTarget{
			name: name,
			path: vars.SharedSecretsPath(cfg.FlakeDir, name),
			kind: targetGroup,
		}, nil
	}
	if err := requireMachineInFlake(cfg, name); err != nil {
		return nil, errors.Wrapf(err, "%q is neither a declared group nor a machine", name)
	}
	return &secretTarget{
		name: name,
		path: vars.MachineSecretsPath(cfg.FlakeDir, name),
		kind: targetMachine,
	}, nil
}

// ensureSecretFile creates the encrypted secrets file for the target if it
// does not already exist. For machine targets this also generates the host
// key (so the machine's age recipient is in place); for group targets it
// re-syncs the per-group .sops.yaml rule from the hosts file.
func ensureSecretFile(cfg *Config, target *secretTarget) error {
	switch target.kind {
	case targetMachine:
		if err := ensureHostKey(cfg, target.name); err != nil {
			return errors.Wrapf(err, "ensure host key for %s", target.name)
		}
		return createEncryptedYAMLIfMissing(cfg, target.path, "machine", target.name)
	case targetGroup:
		if err := reconcileGroups(cfg); err != nil {
			return errors.Wrap(err, "reconcile groups before creating shared secret")
		}
		return createEncryptedYAMLIfMissing(cfg, target.path, "group", target.name)
	default:
		return errors.Errorf("unknown target kind %d", target.kind)
	}
}

func createEncryptedYAMLIfMissing(cfg *Config, path, kind, name string) error {
	if _, err := os.Stat(path); err == nil {
		log.Debug().Str(kind, name).Msg("secrets file already exists")
		return nil
	}
	log.Info().Str(kind, name).Str("file", path).Msg("creating secrets file")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return errors.Wrapf(err, "create dir for %s", path)
	}
	if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
		return errors.Wrapf(err, "write empty secrets for %s", name)
	}
	if err := sops.EncryptYAML(cfg.SopsConf, path); err != nil {
		return errors.Wrapf(err, "encrypt secrets for %s", name)
	}
	return nil
}

func ensureSecrets(cfg *Config, machine string) error {
	if err := ensureHostKey(cfg, machine); err != nil {
		return errors.Wrapf(err, "ensure host key for %s", machine)
	}
	return createEncryptedYAMLIfMissing(cfg, vars.MachineSecretsPath(cfg.FlakeDir, machine), "machine", machine)
}

func verifySecretFile(cfg *Config, path string, fix bool) error {
	log.Info().Str("file", path).Msg("verifying secret")
	if err := sops.VerifyFile(path); err != nil {
		if !fix {
			return err
		}
		log.Warn().Str("file", path).Msg("secret verification failed, attempting repair")
		if repairErr := sops.RepairFile(cfg.SopsConf, path); repairErr != nil {
			return errors.Wrapf(repairErr, "repair secret %s", path)
		}
		if verifyErr := sops.VerifyFile(path); verifyErr != nil {
			return errors.Wrapf(verifyErr, "verify repaired secret %s", path)
		}
		log.Info().Str("file", path).Msg("secret repaired")
		return nil
	}
	log.Info().Str("file", path).Msg("secret verified")
	return nil
}

func verifyAllSecrets(cfg *Config, fix bool) error {
	paths := sops.ListEncryptedFiles(cfg.FlakeDir)
	sort.Strings(paths)
	if len(paths) == 0 {
		log.Info().Msg("no encrypted files found")
		return nil
	}

	for i, path := range paths {
		log.Info().
			Int("index", i+1).
			Int("total", len(paths)).
			Str("file", path).
			Msg("verifying secret")
		if err := sops.VerifyFile(path); err != nil {
			if !fix {
				return err
			}
			log.Warn().
				Int("index", i+1).
				Int("total", len(paths)).
				Str("file", path).
				Msg("secret verification failed, attempting repair")
			if repairErr := sops.RepairFile(cfg.SopsConf, path); repairErr != nil {
				return errors.Wrapf(repairErr, "repair secret %s", path)
			}
			if verifyErr := sops.VerifyFile(path); verifyErr != nil {
				return errors.Wrapf(verifyErr, "verify repaired secret %s", path)
			}
			log.Info().
				Int("index", i+1).
				Int("total", len(paths)).
				Str("file", path).
				Msg("secret repaired")
			continue
		}
		log.Info().
			Int("index", i+1).
			Int("total", len(paths)).
			Str("file", path).
			Msg("secret verified")
	}
	return nil
}

func updateAllSecrets(cfg *Config) error {
	if err := reconcileGroups(cfg); err != nil {
		return err
	}
	paths := sops.ListEncryptedFiles(cfg.FlakeDir)
	sort.Strings(paths)
	if len(paths) == 0 {
		log.Info().Msg("no encrypted files found")
		return nil
	}
	for i, path := range paths {
		log.Info().
			Int("index", i+1).
			Int("total", len(paths)).
			Str("file", path).
			Msg("updating secret keys")
		if err := sops.UpdateKeys(cfg.SopsConf, path); err != nil {
			return errors.Wrapf(err, "update keys for %s", path)
		}
	}
	return nil
}

func listSecretFileKeys(path, label string) error {
	log.Info().Str("file", path).Msg("listing secret keys")
	keys, err := sops.ListYAMLKeys(path)
	if err != nil {
		return err
	}
	for _, key := range keys {
		fmt.Printf("%s\t%s\n", label, key)
	}
	return nil
}

// completionTargetNames returns all names that can be used as a secret target:
// machines and groups from the hosts file, plus basenames of existing secrets YAMLs
// (covers machines that have secrets but no hosts-file address entry).
// Errors are silently ignored -- completion must never fail.
func completionTargetNames(cfg *Config) []string {
	seen := map[string]struct{}{}
	for _, name := range completionMachineOrGroupNames(cfg) {
		seen[name] = struct{}{}
	}
	for _, pat := range []string{
		vars.MachineSecretsGlob(cfg.FlakeDir),
		vars.SharedSecretsGlob(cfg.FlakeDir),
	} {
		if matches, err := filepath.Glob(pat); err == nil {
			for _, p := range matches {
				base := filepath.Base(p)
				seen[base[:len(base)-len(".yaml")]] = struct{}{}
			}
		}
	}
	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// completionExistingTargetNames returns only target names that have an existing
// secrets file on disk.
func completionExistingTargetNames(cfg *Config) []string {
	seen := map[string]struct{}{}
	for _, pat := range []string{
		vars.MachineSecretsGlob(cfg.FlakeDir),
		vars.SharedSecretsGlob(cfg.FlakeDir),
	} {
		if matches, err := filepath.Glob(pat); err == nil {
			for _, p := range matches {
				base := filepath.Base(p)
				seen[base[:len(base)-len(".yaml")]] = struct{}{}
			}
		}
	}
	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// completionTargetKeys returns the top-level YAML keys in the named target's
// secrets file. Returns nil on any error.
func completionTargetKeys(cfg *Config, name string) []string {
	var path string
	if ok, err := hosts.HasGroup(cfg.HostsFile, name); err == nil && ok {
		path = vars.SharedSecretsPath(cfg.FlakeDir, name)
	} else {
		path = vars.MachineSecretsPath(cfg.FlakeDir, name)
	}
	keys, err := sops.ListYAMLKeys(path)
	if err != nil {
		return nil
	}
	return keys
}

func listAllSecrets(cfg *Config) error {
	var paths []string
	for _, pat := range []string{
		vars.MachineSecretsGlob(cfg.FlakeDir),
		vars.SharedSecretsGlob(cfg.FlakeDir),
	} {
		matches, err := filepath.Glob(pat)
		if err != nil {
			return errors.Wrapf(err, "glob %s", pat)
		}
		paths = append(paths, matches...)
	}
	sort.Strings(paths)
	if len(paths) == 0 {
		log.Info().Msg("no secrets found")
		return nil
	}

	for _, path := range paths {
		base := filepath.Base(path)
		name := base[:len(base)-len(".yaml")]
		if err := listSecretFileKeys(path, name); err != nil {
			return err
		}
	}
	return nil
}
