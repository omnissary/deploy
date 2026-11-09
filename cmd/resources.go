package cmd

import (
	"encoding/json"
	"git.tatikoma.dev/corpix/atlas/errors"
	"git.tatikoma.dev/corpix/deploy/internal/atomicfile"
	"git.tatikoma.dev/corpix/deploy/internal/hosts"
	"git.tatikoma.dev/corpix/deploy/internal/manifest"
	"git.tatikoma.dev/corpix/deploy/internal/sops"
	"git.tatikoma.dev/corpix/deploy/internal/vars"
	"os"
	"path/filepath"
	"sort"
)

func provisionApplicationResources(cfg *Config, machine string, meta manifest.Machine) error {
	if cfg.HostsFile == "" && len(meta.Groups)+len(meta.Addresses) == 0 && !meta.Yggdrasil && len(meta.Certificates) == 0 {
		return nil
	}
	groupPath := vars.PublicResourcePath(cfg.FlakeDir, machine, "memberships.json")
	var previous []string
	data, readErr := os.ReadFile(groupPath)
	if readErr == nil {
		if err := json.Unmarshal(data, &previous); err != nil {
			return err
		}
	} else if !os.IsNotExist(readErr) {
		return readErr
	}
	desired := map[string]bool{}
	for _, group := range meta.Groups {
		if _, err := requireGroupName(cfg, group); err != nil {
			return err
		}
		desired[group] = true
	}
	for _, group := range previous {
		if desired[group] {
			continue
		}
		exists, err := hosts.HasGroup(cfg.HostsFile, group)
		if err != nil {
			return err
		}
		if exists {
			if _, err := hosts.RemoveMembers(cfg.HostsFile, group, []string{machine}); err != nil {
				return err
			}
		}
	}
	for _, group := range meta.Groups {
		if _, err := hosts.AddMembers(cfg.HostsFile, group, []string{machine}); err != nil {
			return err
		}
	}
	if len(previous)+len(meta.Groups) > 0 {
		if err := syncAllRecipients(cfg); err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(groupPath), 0755); err != nil {
			return err
		}
		snapshot, _ := json.Marshal(meta.Groups)
		if err := atomicfile.Write(groupPath, append(snapshot, '\n'), 0644); err != nil {
			return err
		}
	}
	for tag, address := range meta.Addresses {
		if tag == "default" {
			tag = ""
		}
		if err := hosts.SetAddress(cfg.HostsFile, machine, tag, address); err != nil {
			return err
		}
	}
	if meta.Yggdrasil {
		if _, err := provisionYggdrasil(cfg, machine, meta, false); err != nil {
			return err
		}
	}
	if len(meta.Certificates) > 0 {
		m, err := loadPolicyManifest(cfg)
		if err != nil {
			return err
		}
		names := append([]string{}, meta.Certificates...)
		sort.Strings(names)
		for _, name := range names {
			spec, ok := m.Certificates[name]
			if !ok {
				return errors.Errorf("undeclared certificate %s", name)
			}
			if spec.Target.Group {
				target, err := resolveSecretTarget(cfg, spec.Target.Name)
				if err != nil {
					return err
				}
				if err := prepareSecretFile(cfg, target); err != nil {
					return err
				}
			}
			if _, err := pkiStore(cfg).Certificate(name, spec, "ensure", false); err != nil {
				return err
			}
		}
	}
	return nil
}

// Required runtime material is checked by key names and public projections only.
// Key matching and decryption remain explicit verification/provisioning work.
func requireApplicationResources(cfg *Config, machine string, meta manifest.Machine) error {
	if meta.Yggdrasil && !fileExists(yggPublicPath(cfg, machine)) {
		return errors.Errorf("missing public Yggdrasil identity; run 'deploy machine provision %s'", machine)
	}
	if len(meta.Certificates) == 0 {
		return nil
	}
	m, err := loadPolicyManifest(cfg)
	if err != nil {
		return err
	}
	for _, name := range meta.Certificates {
		spec, ok := m.Certificates[name]
		if !ok {
			return errors.Errorf("undeclared certificate %s", name)
		}
		if spec.Target.Name == "" {
			continue
		}
		path, err := pkiStore(cfg).TargetPath(spec.Target)
		if err != nil {
			return err
		}
		keys, err := sops.ListYAMLKeys(path)
		if err != nil {
			return err
		}
		present := map[string]bool{}
		for _, key := range keys {
			present[key] = true
		}
		for _, key := range []string{spec.Target.Cert, spec.Target.Key, spec.Target.Chain, spec.Target.CA} {
			if key != "" && !present[key] {
				return errors.Errorf("missing certificate bundle %s; run 'deploy machine provision %s'", name, machine)
			}
		}
	}
	return nil
}
