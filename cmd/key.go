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
					changed, err := sops.AddAdminKey(cfg.SopsConf, cfg.FlakeDir, fingerprint, sops.UpdateKeys)
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
					changed, err := sops.RemoveAdminKey(cfg.SopsConf, cfg.FlakeDir, fingerprint, sops.UpdateKeys)
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

	adminDir := filepath.Join(cfg.FlakeDir, "vars", "admin")
	privPath := filepath.Join(adminDir, name+"-age-key")
	pubPath := privPath + ".pub"

	if fileExists(pubPath) {
		pub, err := os.ReadFile(pubPath)
		if err != nil {
			return errors.Wrapf(err, "read session public key")
		}
		public := strings.TrimSpace(string(pub))
		log.Info().Str("name", name).Msg("session key already exists")
		fmt.Printf("public: %s\n", public)
		changed, err := sops.AddSessionKey(cfg.SopsConf, cfg.FlakeDir, public, sops.UpdateKeys)
		if err != nil {
			return errors.Wrap(err, "sync session key into .sops.yaml")
		}
		if changed {
			log.Info().Str("name", name).Msg("session key synced into .sops.yaml and secrets re-encrypted")
		} else {
			log.Info().Str("name", name).Msg("session key already present in .sops.yaml")
		}
		return nil
	}

	log.Info().Str("name", name).Msg("generating session age key pair")
	if err := os.MkdirAll(adminDir, 0o755); err != nil {
		return errors.Wrapf(err, "create %s", adminDir)
	}

	pair, err := agekey.Generate()
	if err != nil {
		return errors.Wrap(err, "generate session age key")
	}

	if err := sops.Create(cfg.SopsConf, privPath, []byte(pair.Private)); err != nil {
		return errors.Wrap(err, "encrypt session age key")
	}
	if err := os.WriteFile(pubPath, []byte(pair.Public+"\n"), 0o644); err != nil {
		return errors.Wrapf(err, "write session public key")
	}
	log.Info().Str("name", name).Str("public", pair.Public).Msg("session key written")

	if _, err := sops.AddSessionKey(cfg.SopsConf, cfg.FlakeDir, pair.Public, sops.UpdateKeys); err != nil {
		return errors.Wrap(err, "add session key to .sops.yaml")
	}

	fmt.Printf("public: %s\n", pair.Public)
	return nil
}

func unlockSessionKey(cfg *Config, name string) error {
	if err := requireAdminSOPSConfig(cfg); err != nil {
		return err
	}

	privPath := filepath.Join(cfg.FlakeDir, "vars", "admin", name+"-age-key")

	priv, err := sops.ReadFile(privPath)
	if err != nil {
		return errors.Wrapf(err, "decrypt session age key %s", name)
	}

	// Write to XDG_RUNTIME_DIR if available, else a temp dir.
	var dir string
	if xdg := os.Getenv("XDG_RUNTIME_DIR"); xdg != "" {
		dir = filepath.Join(xdg, "sops-"+name)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return errors.Wrapf(err, "create session key dir %s", dir)
		}
	} else {
		dir, err = os.MkdirTemp("", "sops-"+name+"-*")
		if err != nil {
			return errors.Wrap(err, "create temp dir for session key")
		}
	}

	keyFile := filepath.Join(dir, "key")
	if err := os.WriteFile(keyFile, priv, 0o600); err != nil {
		return errors.Wrapf(err, "write session key to %s", keyFile)
	}

	fmt.Printf("export SOPS_AGE_KEY_FILE=%s\n", keyFile)
	return nil
}

func removeSessionKey(cfg *Config, name string) error {
	if err := requireAdminSOPSConfig(cfg); err != nil {
		return err
	}

	privPath := filepath.Join(cfg.FlakeDir, "vars", "admin", name+"-age-key")
	pubPath := privPath + ".pub"

	pub, err := os.ReadFile(pubPath)
	if err != nil {
		return errors.Wrapf(err, "read session public key for %s", name)
	}
	ageKey := string(pub)
	// Trim trailing newline for comparison.
	for len(ageKey) > 0 && (ageKey[len(ageKey)-1] == '\n' || ageKey[len(ageKey)-1] == '\r') {
		ageKey = ageKey[:len(ageKey)-1]
	}

	if _, err := sops.RemoveSessionKey(cfg.SopsConf, cfg.FlakeDir, ageKey, sops.UpdateKeys); err != nil {
		return errors.Wrap(err, "remove session key from .sops.yaml")
	}

	_ = os.Remove(privPath)
	_ = os.Remove(pubPath)
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
			ageKey, err := sshkey.ToAge(pub)
			if err != nil {
				return errors.Wrapf(err, "derive age key for %s", machine)
			}
			_, err = sops.UpsertMachineRules(cfg.SopsConf, cfg.FlakeDir, machine, ageKey, skipUpdateKeys)
			return err
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

	rulesChanged, err := sops.UpsertMachineRules(cfg.SopsConf, cfg.FlakeDir, machine, ageKey, sops.UpdateKeys)
	if err != nil {
		return errors.Wrapf(err, "update sops rules for %s", machine)
	}
	if res == keypair.Generated {
		if err := rekeyMachineFiles(cfg, machine); err != nil {
			return err
		}
	}

	if res != keypair.Existing || rulesChanged {
		fmt.Printf("path: %s\n", pubPath)
		fmt.Printf("ssh:  %s", pubLine)
		fmt.Printf("age:  %s\n", ageKey)
	}
	return nil
}

func skipUpdateKeys(string, string) error { return nil }

// rekeyMachineFiles applies the current creation rules to every existing
// encrypted file of machine.
func rekeyMachineFiles(cfg *Config, machine string) error {
	for _, path := range vars.MachineFiles(cfg.FlakeDir, machine) {
		if !fileExists(path) {
			continue
		}
		if err := sops.UpdateKeys(cfg.SopsConf, path); err != nil {
			return errors.Wrapf(err, "updatekeys %s", path)
		}
	}
	return nil
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

	dir := vars.MachineInitrdKeyDir(cfg.FlakeDir, machine)
	privPath := vars.MachineInitrdKeyPath(cfg.FlakeDir, machine)
	pubPath := vars.MachineInitrdKeyPubPath(cfg.FlakeDir, machine)
	generated := false

	privExists := fileExists(privPath)
	pubExists := fileExists(pubPath)

	switch {
	case privExists && !pubExists:
		return errors.Errorf("missing public key for %s initrd SSH key: %s", machine, pubPath)
	case !privExists && pubExists:
		return errors.Errorf("missing encrypted private key for %s initrd SSH key: %s", machine, privPath)
	case !privExists:
		log.Info().Str("machine", machine).Msg("generating initrd ssh key pair")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return errors.Wrapf(err, "create dir %s", dir)
		}

		pair, err := sshkey.Generate()
		if err != nil {
			return err
		}

		privPEM, err := sshkey.MarshalPrivatePEM(pair)
		if err != nil {
			return err
		}

		comment := fmt.Sprintf("root@%s-initrd", machine)
		pubLine, err := sshkey.MarshalPublicAuthorizedKey(pair, comment)
		if err != nil {
			return err
		}

		if err := sops.Create(cfg.SopsConf, privPath, privPEM); err != nil {
			return errors.Wrapf(err, "encrypt initrd private key for %s", machine)
		}
		if err := os.WriteFile(pubPath, pubLine, 0o644); err != nil {
			return errors.Wrapf(err, "write initrd public key")
		}
		generated = true
		log.Info().Str("machine", machine).Str("path", pubPath).Msg("initrd key written")
	}

	pubLine, err := os.ReadFile(pubPath)
	if err != nil {
		return errors.Wrapf(err, "read initrd public key")
	}

	// Only decrypt and verify immediately after generation. Existing encrypted
	// keys are consumed later during init/deploy; verifying on every build/eval
	// causes an unnecessary secret decryption and YubiKey touch.
	if generated {
		privPEM, err := sops.ReadFile(privPath)
		if err != nil {
			return errors.Wrapf(err, "decrypt initrd private key for %s", machine)
		}
		if err := sshkey.VerifyPair(privPEM, pubLine); err != nil {
			return errors.Wrapf(err, "key pair mismatch for %s initrd key", machine)
		}
	}

	if generated {
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
