package cmd

import (
	"strings"

	"git.tatikoma.dev/corpix/atlas/errors"
	"git.tatikoma.dev/corpix/atlas/log"

	"git.tatikoma.dev/corpix/deploy/internal/hosts"
	"git.tatikoma.dev/corpix/deploy/internal/sops"
)

// loadRecipientModel builds the recipient model from the generic rules in
// .sops.yaml, the host public keys on disk and the groups in the hosts file.
func loadRecipientModel(cfg *Config) (sops.Model, error) {
	groups, err := hosts.Groups(cfg.HostsFile)
	if err != nil {
		return sops.Model{}, errors.Wrap(err, "load groups")
	}
	return sops.LoadModel(cfg.SopsConf, cfg.FlakeDir, groups)
}

// syncRecipients makes .sops.yaml and the recipients of every encrypted file
// match the recipient model, after edit (if not nil) has adjusted it.
func syncRecipients(cfg *Config, edit func(*sops.Model) error) (sops.Plan, error) {
	m, err := loadRecipientModel(cfg)
	if err != nil {
		return sops.Plan{}, err
	}
	if edit != nil {
		if err := edit(&m); err != nil {
			return sops.Plan{}, err
		}
	}
	p, err := sops.Sync(cfg.SopsConf, cfg.FlakeDir, m, sops.UpdateKeys)
	if err != nil {
		return p, err
	}
	if !p.Empty() {
		log.Info().Bool("rules-changed", p.RulesChanged).Int("re-keyed", len(p.Rekey)).Msg("recipients synchronised")
	}
	return p, nil
}

// requireRecipientsInSync fails if .sops.yaml or any file's recipients differ
// from the recipient model. It reads no secret material.
func requireRecipientsInSync(cfg *Config) error {
	m, err := loadRecipientModel(cfg)
	if err != nil {
		return err
	}
	p, err := sops.MakePlan(cfg.SopsConf, cfg.FlakeDir, m)
	if err != nil {
		return err
	}
	if !p.Empty() {
		return errors.Errorf("sops recipients are out of date (%d file(s) to re-encrypt, rules changed: %t); run 'deploy sync' first",
			len(p.Rekey), p.RulesChanged)
	}
	return nil
}

func syncAllRecipients(cfg *Config) error {
	_, err := syncRecipients(cfg, nil)
	return err
}

// addRecipient and removeRecipient edit a key list in place, reporting
// whether it changed. Comparison ignores case for PGP fingerprints.
func addRecipient(list *[]string, key string) bool {
	for _, k := range *list {
		if strings.EqualFold(k, key) {
			return false
		}
	}
	*list = append(*list, key)
	return true
}

func removeRecipient(list *[]string, key string) bool {
	out := (*list)[:0:0]
	for _, k := range *list {
		if !strings.EqualFold(k, key) {
			out = append(out, k)
		}
	}
	changed := len(out) != len(*list)
	*list = out
	return changed
}

func addAdminKey(cfg *Config, fingerprint string) (bool, error) {
	var changed bool
	_, err := syncRecipients(cfg, func(m *sops.Model) error {
		changed = addRecipient(&m.Admins, fingerprint)
		return nil
	})
	return changed, err
}

func removeAdminKey(cfg *Config, fingerprint string) (bool, error) {
	var changed bool
	_, err := syncRecipients(cfg, func(m *sops.Model) error {
		changed = removeRecipient(&m.Admins, fingerprint)
		if len(m.Admins) == 0 {
			return errors.New("cannot remove the last admin PGP recipient")
		}
		return nil
	})
	return changed, err
}
