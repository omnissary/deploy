package cmd

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

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
					val, err := getSecret(target.path, key)
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
					if err := prepareSecretFile(cfg, target); err != nil {
						return err
					}
					key := ctx.Args().Get(1)
					log.Debug().Str("target", target.name).Str("key", key).Msg("secret set")
					raw, err := io.ReadAll(os.Stdin)
					if err != nil {
						return errors.Wrap(err, "read stdin")
					}
					if err := setSecret(target.path, key, secretValueFromInput(raw)); err != nil {
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
					if err := deleteSecret(target.path, key); err != nil {
						return errors.Wrapf(err, "del secret %s/%s", target.name, key)
					}
					log.Info().Str("target", target.name).Str("key", key).Msg("secret deleted")
					return nil
				},
			},
			{
				Name:      "update",
				Usage:     "regenerate .sops.yaml and re-encrypt files whose recipients are out of date; with a name, also re-encrypt that file unconditionally",
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
						return syncAllRecipients(cfg)
					}
					target, err := resolveSecretTarget(cfg, ctx.Args().Get(0))
					if err != nil {
						return err
					}
					if !fileExists(target.path) {
						return errors.Errorf("no secrets file at %s", target.path)
					}
					if err := syncAllRecipients(cfg); err != nil {
						return err
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
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:  "force",
						Usage: "overwrite the destination key if it already exists",
					},
				},
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
					if err := prepareSecretFile(cfg, dst); err != nil {
						return err
					}
					if err := moveSecret(src.path, srcKey, dst.path, dstKey, ctx.Bool("force")); err != nil {
						return errors.Wrapf(err, "move secret %s/%s to %s/%s", src.name, srcKey, dst.name, dstKey)
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
				Usage:     "verify decryption and integrity of a target, or of every encrypted file",
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
					if ctx.NArg() < 1 {
						return verifyAllSecrets(cfg)
					}
					target, err := resolveSecretTarget(cfg, ctx.Args().Get(0))
					if err != nil {
						return err
					}
					if !fileExists(target.path) {
						return errors.Errorf("no secrets file at %s", target.path)
					}
					return verifyFiles([]string{target.path})
				},
			},
			{
				Name:      "repair",
				Usage:     "re-sign a file whose integrity check fails, after confirming its decrypted keys",
				ArgsUsage: "<name> | --file <path>",
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
					&cli.StringFlag{
						Name:  "file",
						Usage: "repair an encrypted file by path instead of by target name",
					},
					&cli.BoolFlag{
						Name:  "yes",
						Usage: "accept the decrypted content without prompting",
					},
				},
				Action: func(ctx *cli.Context) error {
					cfg := getConfig(ctx)
					path := ctx.String("file")
					switch {
					case path != "" && ctx.NArg() > 0:
						return errors.New("pass either <name> or --file, not both")
					case path == "" && ctx.NArg() == 0:
						return errors.New("usage: secret repair <name> | --file <path>")
					case path == "":
						target, err := resolveSecretTarget(cfg, ctx.Args().Get(0))
						if err != nil {
							return err
						}
						path = target.path
					}
					if !fileExists(path) {
						return errors.Errorf("no encrypted file at %s", path)
					}
					accept := promptRepair(os.Stdin, os.Stderr)
					if ctx.Bool("yes") {
						accept = func(*sops.File) (bool, error) { return true, nil }
					}
					return repairSecretFile(cfg, path, accept)
				},
			},
		},
	}
}

func getSecret(path, key string) (string, error) {
	f, err := sops.Open(path)
	if err != nil {
		return "", err
	}
	return f.Get(key)
}

func setSecret(path, key, value string) error {
	return sops.Edit(path, func(f *sops.File) error {
		f.Set(key, value)
		return nil
	})
}

func deleteSecret(path, key string) error {
	return sops.Edit(path, func(f *sops.File) error {
		return f.Delete(key)
	})
}

// moveSecret moves srcKey in srcPath to dstKey in dstPath, refusing to replace
// an existing destination key unless overwrite is set. Within one file the
// move is a single atomic rewrite. Across files the destination is written
// before the source key is deleted, so a failure can only leave a duplicate.
func moveSecret(srcPath, srcKey, dstPath, dstKey string, overwrite bool) error {
	if srcPath == dstPath && srcKey == dstKey {
		return errors.New("source and destination are identical")
	}
	if srcPath == dstPath {
		return sops.Edit(srcPath, func(f *sops.File) error {
			val, err := f.Get(srcKey)
			if err != nil {
				return err
			}
			if err := checkMoveDestination(f, dstKey, overwrite); err != nil {
				return err
			}
			f.Set(dstKey, val)
			return f.Delete(srcKey)
		})
	}

	src, err := sops.Open(srcPath)
	if err != nil {
		return err
	}
	val, err := src.Get(srcKey)
	if err != nil {
		return err
	}
	if err := sops.Edit(dstPath, func(f *sops.File) error {
		if err := checkMoveDestination(f, dstKey, overwrite); err != nil {
			return err
		}
		f.Set(dstKey, val)
		return nil
	}); err != nil {
		return err
	}
	if err := src.Delete(srcKey); err != nil {
		return err
	}
	return src.Save()
}

func checkMoveDestination(f *sops.File, key string, overwrite bool) error {
	if !overwrite && f.Has(key) {
		return errors.Errorf("key %q already exists in %s; use --force to overwrite", key, f.Path())
	}
	return nil
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
	if _, err := requireMachineName(name); err != nil {
		return nil, err
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

// prepareSecretFile makes sure the target's secrets file exists without
// generating keys or re-keying anything. A machine must already have a host
// key, and a new file is only created while recipients are in sync, so it is
// encrypted for exactly the recipients its rule describes.
func prepareSecretFile(cfg *Config, target *secretTarget) error {
	if fileExists(target.path) {
		return nil
	}
	if target.kind == targetMachine && !fileExists(vars.MachineHostKeyPubPath(cfg.FlakeDir, target.name)) {
		return errors.Errorf("machine %s has no host key yet; run 'deploy machine provision %s' first", target.name, target.name)
	}
	if err := requireRecipientsInSync(cfg); err != nil {
		return err
	}
	kind := "machine"
	if target.kind == targetGroup {
		kind = "group"
	}
	return createEncryptedYAMLIfMissing(cfg, target.path, kind, target.name)
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
	if err := sops.Create(cfg.SopsConf, path, []byte("{}\n")); err != nil {
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

func verifyAllSecrets(cfg *Config) error {
	paths := sops.ListEncryptedFiles(cfg.FlakeDir)
	sort.Strings(paths)
	if len(paths) == 0 {
		log.Info().Msg("no encrypted files found")
		return nil
	}
	return verifyFiles(paths)
}

// verifyFiles checks every path and reports all failures together rather than
// stopping at the first one.
func verifyFiles(paths []string) error {
	var failed []string
	for i, path := range paths {
		if err := sops.Verify(path); err != nil {
			log.Error().Err(err).Int("index", i+1).Int("total", len(paths)).Str("file", path).Msg("secret verification failed")
			failed = append(failed, path)
			continue
		}
		log.Info().Int("index", i+1).Int("total", len(paths)).Str("file", path).Msg("secret verified")
	}
	if len(failed) > 0 {
		return errors.Errorf("%d of %d secret files failed verification; inspect them and use 'secret repair':\n  %s",
			len(failed), len(paths), strings.Join(failed, "\n  "))
	}
	return nil
}

func repairSecretFile(cfg *Config, path string, accept func(*sops.File) (bool, error)) error {
	repaired, err := sops.Repair(cfg.SopsConf, path, accept)
	if err != nil {
		return errors.Wrapf(err, "repair %s", path)
	}
	if !repaired {
		log.Info().Str("file", path).Msg("secret verifies, nothing to repair")
		return nil
	}
	log.Info().Str("file", path).Msg("secret repaired")
	return nil
}

// promptRepair asks on out whether content decrypted without the integrity
// check should be re-signed, reading the answer from in.
func promptRepair(in io.Reader, out io.Writer) func(*sops.File) (bool, error) {
	return func(f *sops.File) (bool, error) {
		fmt.Fprintf(out, "%s failed its integrity check: it was modified outside of sops or is corrupted.\n", f.Path())
		fmt.Fprintf(out, "Decrypted without the check, it contains these keys:\n")
		for _, k := range f.Keys() {
			fmt.Fprintf(out, "  %s\n", k)
		}
		fmt.Fprintf(out, "Re-sign this content as trusted? [y/N] ")
		answer, err := bufio.NewReader(in).ReadString('\n')
		if err != nil && err != io.EOF {
			return false, errors.Wrap(err, "read answer")
		}
		switch strings.ToLower(strings.TrimSpace(answer)) {
		case "y", "yes":
			return true, nil
		default:
			return false, nil
		}
	}
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
