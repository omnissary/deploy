package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"git.tatikoma.dev/corpix/atlas/errors"
	"git.tatikoma.dev/corpix/atlas/log"
	"github.com/urfave/cli/v2"

	"git.tatikoma.dev/corpix/deploy/internal/agekey"
	"git.tatikoma.dev/corpix/deploy/internal/atomicfile"
	"git.tatikoma.dev/corpix/deploy/internal/keypair"
	"git.tatikoma.dev/corpix/deploy/internal/sops"
	"git.tatikoma.dev/corpix/deploy/internal/sshkey"
	"git.tatikoma.dev/corpix/deploy/internal/vars"
)

func keyCmd() *cli.Command {
	return &cli.Command{
		Name:  "key",
		Usage: "manage per-machine SSH key pairs and SOPS recipients",
		Before: func(ctx *cli.Context) error {
			return requireFlake(getConfig(ctx))
		},
		Subcommands: []*cli.Command{
			yggdrasilCmd(),
			{
				Name:      "host",
				Usage:     "ensure the openssh host key exists and is encrypted",
				ArgsUsage: "<machine>",
				BashComplete: func(ctx *cli.Context) {
					cfg := completionConfig(ctx)
					if ctx.NArg() == 0 {
						for _, name := range completionMachineNames(cfg) {
							fmt.Println(name)
						}
					}
				},
				Action: func(ctx *cli.Context) error {
					if ctx.NArg() < 1 {
						return errors.New("usage: key host <machine>")
					}
					cfg := getConfig(ctx)
					machine, err := requireMachine(cfg, ctx.Args().Get(0))
					if err != nil {
						return err
					}
					return ensureHostKey(cfg, machine)
				},
			},
			{
				Name:      "initrd",
				Usage:     "ensure the initrd SSH key exists and is encrypted",
				ArgsUsage: "<machine>",
				BashComplete: func(ctx *cli.Context) {
					cfg := completionConfig(ctx)
					if ctx.NArg() == 0 {
						for _, name := range completionMachineNames(cfg) {
							fmt.Println(name)
						}
					}
				},
				Action: func(ctx *cli.Context) error {
					if ctx.NArg() < 1 {
						return errors.New("usage: key initrd <machine>")
					}
					cfg := getConfig(ctx)
					machine, err := requireMachine(cfg, ctx.Args().Get(0))
					if err != nil {
						return err
					}
					return ensureInitrdKey(cfg, machine)
				},
			},
			{
				Name:      "ensure",
				Usage:     "ensure both host and initrd keys exist",
				ArgsUsage: "<machine>",
				BashComplete: func(ctx *cli.Context) {
					cfg := completionConfig(ctx)
					if ctx.NArg() == 0 {
						for _, name := range completionMachineNames(cfg) {
							fmt.Println(name)
						}
					}
				},
				Action: func(ctx *cli.Context) error {
					if ctx.NArg() < 1 {
						return errors.New("usage: key ensure <machine>")
					}
					cfg := getConfig(ctx)
					machine, err := requireMachine(cfg, ctx.Args().Get(0))
					if err != nil {
						return err
					}
					if err := ensureHostKey(cfg, machine); err != nil {
						return err
					}
					return ensureInitrdKey(cfg, machine)
				},
			},
			keyAdminCmd(),
			keySessionCmd(),
		},
	}
}

func requireAdminSOPSConfig(cfg *Config) error {
	if err := sops.RequireAdminPGPConfig(cfg.SopsConf); err != nil {
		return errors.Wrap(err, "validate sops admin recipients")
	}
	return nil
}

func keyAdminCmd() *cli.Command {
	return &cli.Command{
		Name:  "admin",
		Usage: "manage admin PGP recipients in .sops.yaml",
		Subcommands: []*cli.Command{
			{
				Name:  "list",
				Usage: "print admin PGP fingerprints",
				Action: func(ctx *cli.Context) error {
					cfg := getConfig(ctx)
					if err := requireAdminSOPSConfig(cfg); err != nil {
						return err
					}
					keys, err := sops.ListAdminKeys(cfg.SopsConf)
					if err != nil {
						return err
					}
					for _, k := range keys {
						fmt.Println(k)
					}
					return nil
				},
			},
			{
				Name:      "add",
				Usage:     "add an admin PGP fingerprint to all creation rules",
				ArgsUsage: "<fingerprint>",
				Action: func(ctx *cli.Context) error {
					if ctx.NArg() < 1 {
						return errors.New("usage: key admin add <fingerprint>")
					}
					cfg := getConfig(ctx)
					if err := requireAdminSOPSConfig(cfg); err != nil {
						return err
					}
					fingerprint := ctx.Args().Get(0)
					changed, err := addAdminKey(cfg, fingerprint)
					if err != nil {
						return err
					}
					if changed {
						log.Info().Str("fingerprint", fingerprint).Msg("admin key added and secrets re-encrypted")
					} else {
						log.Info().Str("fingerprint", fingerprint).Msg("admin key already present")
					}
					return nil
				},
			},
			{
				Name:      "remove",
				Usage:     "remove an admin PGP fingerprint from all creation rules",
				ArgsUsage: "<fingerprint>",
				Action: func(ctx *cli.Context) error {
					if ctx.NArg() < 1 {
						return errors.New("usage: key admin remove <fingerprint>")
					}
					cfg := getConfig(ctx)
					if err := requireAdminSOPSConfig(cfg); err != nil {
						return err
					}
					fingerprint := ctx.Args().Get(0)
					changed, err := removeAdminKey(cfg, fingerprint)
					if err != nil {
						return err
					}
					if changed {
						log.Info().Str("fingerprint", fingerprint).Msg("admin key removed and secrets re-encrypted")
					} else {
						log.Info().Str("fingerprint", fingerprint).Msg("admin key not found")
					}
					return nil
				},
			},
		},
	}
}

func keySessionCmd() *cli.Command {
	nameFlag := &cli.StringFlag{
		Name:  "name",
		Usage: "session key name (used as filename under vars/admin/)",
		Value: "session",
	}
	return &cli.Command{
		Name:  "session",
		Usage: "manage dev-session age keys (one YubiKey touch per shell)",
		Subcommands: []*cli.Command{
			{
				Name:  "list",
				Usage: "print session age public keys",
				Action: func(ctx *cli.Context) error {
					cfg := getConfig(ctx)
					if err := requireAdminSOPSConfig(cfg); err != nil {
						return err
					}
					keys, err := sops.ListSessionKeys(cfg.SopsConf)
					if err != nil {
						return err
					}
					for _, k := range keys {
						fmt.Println(k)
					}
					return nil
				},
			},
			{
				Name:  "ensure",
				Usage: "generate a session age key if it does not exist",
				Flags: []cli.Flag{nameFlag},
				Action: func(ctx *cli.Context) error {
					cfg := getConfig(ctx)
					name := ctx.String("name")
					return ensureSessionKey(cfg, name)
				},
			},
			{
				Name:  "unlock",
				Usage: "decrypt session age key and emit SOPS_AGE_KEY_FILE export",
				Flags: []cli.Flag{nameFlag},
				Action: func(ctx *cli.Context) error {
					cfg := getConfig(ctx)
					return unlockSessionKey(cfg, ctx.String("name"))
				},
			},
			{
				Name:      "remove",
				Usage:     "remove a session age key from .sops.yaml and delete its files",
				ArgsUsage: "<name>",
				Action: func(ctx *cli.Context) error {
					if ctx.NArg() < 1 {
						return errors.New("usage: key session remove <name>")
					}
					cfg := getConfig(ctx)
					return removeSessionKey(cfg, ctx.Args().Get(0))
				},
			},
		},
	}
}

func ensureSessionKey(cfg *Config, name string) error {
	if err := requireAdminSOPSConfig(cfg); err != nil {
		return err
	}
	name, err := requireSimpleName("session key", name)
	if err != nil {
		return err
	}

	pubPath := vars.SessionKeyPubPath(cfg.FlakeDir, name)
	res, err := keypair.Ensure(cfg.SopsConf, keypair.Spec{
		Name: name + " session key",
		Priv: vars.SessionKeyPath(cfg.FlakeDir, name),
		Pub:  pubPath,
		Generate: func() ([]byte, []byte, error) {
			pair, err := agekey.Generate()
			if err != nil {
				return nil, nil, err
			}
			return []byte(pair.Private), []byte(pair.Public + "\n"), nil
		},
		Derive: func(priv []byte) ([]byte, error) {
			public, err := agekey.PublicFromPrivate(string(priv))
			if err != nil {
				return nil, err
			}
			return []byte(public + "\n"), nil
		},
	})
	if err != nil {
		return err
	}

	public, err := readSessionPublicKey(cfg, name)
	if err != nil {
		return err
	}
	if res == keypair.Existing {
		log.Info().Str("name", name).Msg("session key already exists")
	}
	var changed bool
	_, err = syncRecipients(cfg, func(m *sops.Model) error {
		changed = addRecipient(&m.Sessions, public)
		return nil
	})
	if err != nil {
		return errors.Wrap(err, "add session key to .sops.yaml")
	}
	if changed {
		log.Info().Str("name", name).Msg("session key added to .sops.yaml and secrets re-encrypted")
	}
	fmt.Printf("public: %s\n", public)
	return nil
}

func readSessionPublicKey(cfg *Config, name string) (string, error) {
	pub, err := os.ReadFile(vars.SessionKeyPubPath(cfg.FlakeDir, name))
	if err != nil {
		return "", errors.Wrapf(err, "read session public key for %s", name)
	}
	return strings.TrimSpace(string(pub)), nil
}

func unlockSessionKey(cfg *Config, name string) error {
	if err := requireAdminSOPSConfig(cfg); err != nil {
		return err
	}

	name, err := requireSimpleName("session key", name)
	if err != nil {
		return err
	}

	runtimeDir := os.Getenv("XDG_RUNTIME_DIR")
	if runtimeDir == "" {
		return errors.New("XDG_RUNTIME_DIR is not set; refusing to write a decrypted session key to persistent storage")
	}

	priv, err := sops.ReadFile(vars.SessionKeyPath(cfg.FlakeDir, name))
	if err != nil {
		return errors.Wrapf(err, "decrypt session age key %s", name)
	}

	keyFile, err := writeSessionKeyFile(runtimeDir, name, priv)
	if err != nil {
		return err
	}

	fmt.Printf("export SOPS_AGE_KEY_FILE=%s\n", keyFile)
	return nil
}

// writeSessionKeyFile stores a decrypted session key under the per-user
// runtime directory, which is private to the user and cleared on logout.
func writeSessionKeyFile(runtimeDir, name string, priv []byte) (string, error) {
	if runtimeDir == "" {
		return "", errors.New("XDG_RUNTIME_DIR is not set; refusing to write a decrypted session key to persistent storage")
	}
	dir := filepath.Join(runtimeDir, "sops-"+name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", errors.Wrapf(err, "create session key dir %s", dir)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return "", errors.Wrapf(err, "restrict session key dir %s", dir)
	}
	keyFile := filepath.Join(dir, "key")
	if err := atomicfile.Write(keyFile, priv, 0o600); err != nil {
		return "", errors.Wrapf(err, "write session key to %s", keyFile)
	}
	return keyFile, nil
}

func removeSessionKey(cfg *Config, name string) error {
	if err := requireAdminSOPSConfig(cfg); err != nil {
		return err
	}

	name, err := requireSimpleName("session key", name)
	if err != nil {
		return err
	}
	ageKey, err := readSessionPublicKey(cfg, name)
	if err != nil {
		return err
	}

	if _, err := syncRecipients(cfg, func(m *sops.Model) error {
		if !removeRecipient(&m.Sessions, ageKey) {
			return errors.Errorf("session key %s is not a recipient in %s", name, cfg.SopsConf)
		}
		return nil
	}); err != nil {
		return errors.Wrap(err, "remove session key from .sops.yaml")
	}

	_ = os.Remove(vars.SessionKeyPath(cfg.FlakeDir, name))
	_ = os.Remove(vars.SessionKeyPubPath(cfg.FlakeDir, name))
	log.Info().Str("name", name).Msg("session key removed")
	return nil
}

func ensureSopsConf(cfg *Config) error {
	if !fileExists(cfg.SopsConf) {
		return errors.Errorf("missing %s; run 'deploy init --admin-pgp <fingerprint>' first", cfg.SopsConf)
	}
	return requireAdminSOPSConfig(cfg)
}

func ensureHostKey(cfg *Config, machine string) error {
	if err := requireAdminSOPSConfig(cfg); err != nil {
		return err
	}

	pubPath := vars.MachineHostKeyPubPath(cfg.FlakeDir, machine)
	res, err := keypair.Ensure(cfg.SopsConf, keypair.Spec{
		Name:     machine + " host key",
		Priv:     vars.MachineHostKeyPath(cfg.FlakeDir, machine),
		Pub:      pubPath,
		Generate: sshKeyGenerator(""),
		Derive:   sshKeyDeriver(""),
		Prepare: func(pub []byte) error {
			return installMachineRules(cfg, machine, pub)
		},
	})
	if err != nil {
		return err
	}

	pubLine, err := os.ReadFile(pubPath)
	if err != nil {
		return errors.Wrapf(err, "read host public key")
	}
	ageKey, err := sshkey.ToAge(pubLine)
	if err != nil {
		return errors.Wrapf(err, "derive age key for %s", machine)
	}
	log.Debug().Str("machine", machine).Str("age", ageKey).Msg("derived age key")

	plan, err := syncRecipients(cfg, nil)
	if err != nil {
		return errors.Wrapf(err, "update sops recipients for %s", machine)
	}

	if res != keypair.Existing || !plan.Empty() {
		fmt.Printf("path: %s\n", pubPath)
		fmt.Printf("ssh:  %s", pubLine)
		fmt.Printf("age:  %s\n", ageKey)
	}
	return nil
}

// installMachineRules writes the creation rules for a machine whose host key
// is about to be created, without re-keying anything: the key does not exist
// yet, so no file may be encrypted for it before it is on disk.
func installMachineRules(cfg *Config, machine string, pub []byte) error {
	ageKey, err := sshkey.ToAge(pub)
	if err != nil {
		return errors.Wrapf(err, "derive age key for %s", machine)
	}
	m, err := loadRecipientModel(cfg)
	if err != nil {
		return err
	}
	m.Machines[machine] = ageKey
	p, err := sops.MakePlan(cfg.SopsConf, cfg.FlakeDir, m)
	if err != nil {
		return err
	}
	p.Rekey = nil
	return sops.Apply(cfg.SopsConf, p, nil)
}

func sshKeyGenerator(comment string) func() ([]byte, []byte, error) {
	return func() ([]byte, []byte, error) {
		pair, err := sshkey.Generate()
		if err != nil {
			return nil, nil, err
		}
		priv, err := sshkey.MarshalPrivatePEM(pair)
		if err != nil {
			return nil, nil, err
		}
		pub, err := sshkey.MarshalPublicAuthorizedKey(pair, comment)
		if err != nil {
			return nil, nil, err
		}
		return priv, pub, nil
	}
}

func sshKeyDeriver(comment string) func([]byte) ([]byte, error) {
	return func(priv []byte) ([]byte, error) {
		return sshkey.PublicFromPrivate(priv, comment)
	}
}

func ensureInitrdKey(cfg *Config, machine string) error {
	if err := requireAdminSOPSConfig(cfg); err != nil {
		return err
	}

	privPath := vars.MachineInitrdKeyPath(cfg.FlakeDir, machine)
	pubPath := vars.MachineInitrdKeyPubPath(cfg.FlakeDir, machine)
	comment := fmt.Sprintf("root@%s-initrd", machine)
	res, err := keypair.Ensure(cfg.SopsConf, keypair.Spec{
		Name:     machine + " initrd key",
		Priv:     privPath,
		Pub:      pubPath,
		Generate: sshKeyGenerator(comment),
		Derive:   sshKeyDeriver(comment),
	})
	if err != nil {
		return err
	}

	if res != keypair.Existing {
		pubLine, err := os.ReadFile(pubPath)
		if err != nil {
			return errors.Wrapf(err, "read initrd public key")
		}
		fmt.Printf("secret:      %s\n", privPath)
		fmt.Printf("deploy path: /etc/secrets/initrd_host_ed25519_key\n")
		fmt.Printf("public:      %s", pubLine)
	}
	return nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
