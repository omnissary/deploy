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
	"git.tatikoma.dev/corpix/deploy/internal/sops"
	"git.tatikoma.dev/corpix/deploy/internal/sshkey"
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

	encrypted, err := sops.EncryptBinary(cfg.SopsConf, privPath, []byte(pair.Private))
	if err != nil {
		return errors.Wrap(err, "encrypt session age key")
	}
	if err := os.WriteFile(privPath, encrypted, 0o600); err != nil {
		return errors.Wrapf(err, "write encrypted session key")
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
	privPath := filepath.Join(cfg.FlakeDir, "vars", "admin", name+"-age-key")

	priv, err := sops.DecryptBinary(privPath)
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

func ensureHostKey(cfg *Config, machine string) error {
	dir := filepath.Join(cfg.FlakeDir, "vars", "per-machine", machine, "openssh")
	pubPath := filepath.Join(dir, "ssh_host_ed25519_key.pub")
	privPath := filepath.Join(dir, "ssh_host_ed25519_key")
	generated := false

	if _, err := os.Stat(pubPath); err == nil {
		log.Debug().Str("machine", machine).Msg("host key already exists")
	} else {
		log.Info().Str("machine", machine).Msg("generating host ssh key pair")
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

		pubLine, err := sshkey.MarshalPublicAuthorizedKey(pair, "")
		if err != nil {
			return err
		}

		encrypted, err := sops.EncryptBinary(cfg.SopsConf, privPath, privPEM)
		if err != nil {
			return errors.Wrapf(err, "encrypt host private key for %s", machine)
		}
		if err := os.WriteFile(privPath, encrypted, 0o600); err != nil {
			return errors.Wrapf(err, "write encrypted host private key")
		}
		if err := os.WriteFile(pubPath, pubLine, 0o644); err != nil {
			return errors.Wrapf(err, "write host public key")
		}
		generated = true
		log.Info().Str("machine", machine).Str("path", pubPath).Msg("host key written")
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

	rulesChanged, err := sops.UpsertMachineRules(cfg.SopsConf, machine, ageKey, sops.UpdateKeys)
	if err != nil {
		return errors.Wrapf(err, "update sops rules for %s", machine)
	}

	if generated || rulesChanged {
		fmt.Printf("path: %s\n", pubPath)
		fmt.Printf("ssh:  %s", pubLine)
		fmt.Printf("age:  %s\n", ageKey)
	}
	return nil
}

func ensureInitrdKey(cfg *Config, machine string) error {
	dir := filepath.Join(cfg.FlakeDir, "vars", "per-machine", machine, "initrd-ssh")
	privPath := filepath.Join(dir, "id_ed25519")
	pubPath := filepath.Join(dir, "id_ed25519.pub")
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

		encrypted, err := sops.EncryptBinary(cfg.SopsConf, privPath, privPEM)
		if err != nil {
			return errors.Wrapf(err, "encrypt initrd private key for %s", machine)
		}
		if err := os.WriteFile(privPath, encrypted, 0o600); err != nil {
			return errors.Wrapf(err, "write encrypted initrd private key")
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
		privPEM, err := sops.DecryptBinary(privPath)
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
