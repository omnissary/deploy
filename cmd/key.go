package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"git.tatikoma.dev/corpix/atlas/errors"
	"git.tatikoma.dev/corpix/atlas/log"
	"github.com/urfave/cli/v2"

	"git.tatikoma.dev/corpix/deploy/internal/sops"
	"git.tatikoma.dev/corpix/deploy/internal/sopsrules"
	"git.tatikoma.dev/corpix/deploy/internal/sshkey"
)

func keyCmd() *cli.Command {
	return &cli.Command{
		Name:  "key",
		Usage: "manage per-machine SSH key pairs",
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
					return ensureHostKey(cfg, ctx.Args().Get(0))
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
					return ensureInitrdKey(cfg, ctx.Args().Get(0))
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
					machine := ctx.Args().Get(0)
					if err := ensureHostKey(cfg, machine); err != nil {
						return err
					}
					return ensureInitrdKey(cfg, machine)
				},
			},
		},
	}
}

func ensureHostKey(cfg *Config, machine string) error {
	dir := filepath.Join(cfg.FlakeDir, "vars", "per-machine", machine, "openssh")
	pubPath := filepath.Join(dir, "ssh_host_ed25519_key.pub")
	privPath := filepath.Join(dir, "ssh_host_ed25519_key")

	if _, err := os.Stat(pubPath); err == nil {
		log.Debug().Str("machine", machine).Msg("host key already exists")
	} else {
		log.Info().Str("machine", machine).Msg("generating host SSH key pair")
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

	if _, err := sopsrules.UpsertMachineRules(cfg.SopsConf, machine, ageKey, sops.UpdateKeys); err != nil {
		return errors.Wrapf(err, "update sops rules for %s", machine)
	}

	fmt.Printf("path: %s\n", pubPath)
	fmt.Printf("ssh:  %s", pubLine)
	fmt.Printf("age:  %s\n", ageKey)
	return nil
}

func ensureInitrdKey(cfg *Config, machine string) error {
	dir := filepath.Join(cfg.FlakeDir, "vars", "per-machine", machine, "initrd-ssh")
	privPath := filepath.Join(dir, "id_ed25519")
	pubPath := filepath.Join(dir, "id_ed25519.pub")

	privExists := fileExists(privPath)
	pubExists := fileExists(pubPath)

	switch {
	case privExists && !pubExists:
		return errors.Errorf("missing public key for %s initrd SSH key: %s", machine, pubPath)
	case !privExists && pubExists:
		return errors.Errorf("missing encrypted private key for %s initrd SSH key: %s", machine, privPath)
	case !privExists:
		log.Info().Str("machine", machine).Msg("generating initrd SSH key pair")
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
		log.Info().Str("machine", machine).Str("path", pubPath).Msg("initrd key written")
	}

	// Verify key pair integrity.
	privPEM, err := sops.DecryptBinary(privPath)
	if err != nil {
		return errors.Wrapf(err, "decrypt initrd private key for %s", machine)
	}
	pubLine, err := os.ReadFile(pubPath)
	if err != nil {
		return errors.Wrapf(err, "read initrd public key")
	}
	if err := sshkey.VerifyPair(privPEM, pubLine); err != nil {
		return errors.Wrapf(err, "key pair mismatch for %s initrd key", machine)
	}

	fmt.Printf("secret:      %s\n", privPath)
	fmt.Printf("deploy path: /etc/secrets/initrd_host_ed25519_key\n")
	fmt.Printf("public:      %s", pubLine)
	return nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
