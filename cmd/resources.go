package cmd

import (
	"git.tatikoma.dev/corpix/atlas/errors"
	"git.tatikoma.dev/corpix/deploy/internal/manifest"
	"git.tatikoma.dev/corpix/deploy/internal/sops"
	"git.tatikoma.dev/corpix/deploy/internal/vars"
)

func requireSecrets(cfg *Config, references []manifest.SecretRef) error {
	for _, ref := range references {
		path := vars.MachineSecretsPath(cfg.FlakeDir, ref.Name)
		if ref.Group {
			path = vars.SharedSecretsPath(cfg.FlakeDir, ref.Name)
		}
		keys, err := sops.ListYAMLKeys(path)
		if err != nil {
			return errors.Wrapf(err, "required secret %s/%s", ref.Name, ref.Key)
		}
		found := false
		for _, key := range keys {
			if key == ref.Key {
				found = true
				break
			}
		}
		if !found {
			return errors.Errorf("missing required secret %s in %s", ref.Key, relToFlake(cfg, path))
		}
	}
	return nil
}

func storageSecrets(machine string, meta manifest.Machine) []manifest.SecretRef {
	references := make([]manifest.SecretRef, 0, len(meta.Pools))
	for _, pool := range meta.Pools {
		references = append(references, manifest.SecretRef{Name: machine, Key: pool.Secret})
	}
	return references
}

func requireUnlockCredentials(cfg *Config, machine string, meta manifest.Machine) error {
	if !meta.InitrdSSH {
		return errors.New("machine has no managed initrd SSH capability")
	}
	switch meta.Unlock {
	case "luks":
		return nil
	case "zfs":
		if len(meta.Pools) == 0 {
			return errors.New("no encrypted ZFS pools declared")
		}
		return requireSecrets(cfg, storageSecrets(machine, meta))
	default:
		return errors.New("no supported unlock capability declared")
	}
}
