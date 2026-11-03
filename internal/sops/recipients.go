package sops

import (
	"sort"
	"strings"

	"github.com/getsops/sops/v3/age"
	"github.com/getsops/sops/v3/cmd/sops/common"
	"github.com/getsops/sops/v3/cmd/sops/formats"
	"github.com/getsops/sops/v3/config"
	"github.com/getsops/sops/v3/pgp"

	"git.tatikoma.dev/corpix/atlas/errors"
)

// Recipients is a single key group: everyone who can decrypt a file on their
// own. Both lists are sorted and free of duplicates.
type Recipients struct {
	PGP []string
	Age []string
}

// NewRecipients builds a normalised Recipients value.
func NewRecipients(pgpKeys, ageKeys []string) Recipients {
	return Recipients{PGP: normalizeKeys(pgpKeys, strings.ToUpper), Age: normalizeKeys(ageKeys, nil)}
}

// Equal reports whether both sets contain the same keys.
func (r Recipients) Equal(o Recipients) bool {
	return stringSliceEqual(r.PGP, o.PGP) && stringSliceEqual(r.Age, o.Age)
}

// ReadRecipients returns the recipients recorded in the SOPS metadata of path
// without decrypting anything. Files using several key groups, a Shamir
// threshold or key types other than PGP and age are reported as an error,
// since this tool never produces them.
func ReadRecipients(path string) (Recipients, error) {
	store := common.StoreForFormat(formats.FormatForPath(path), config.NewStoresConfig())
	tree, err := common.LoadEncryptedFile(store, path)
	if err != nil {
		return Recipients{}, errors.Wrapf(err, "sops load encrypted %s", path)
	}
	groups := tree.Metadata.KeyGroups
	if len(groups) != 1 {
		return Recipients{}, errors.Errorf("%s uses %d key groups, expected 1", path, len(groups))
	}
	var pgpKeys, ageKeys []string
	for _, key := range groups[0] {
		switch k := key.(type) {
		case *pgp.MasterKey:
			pgpKeys = append(pgpKeys, k.Fingerprint)
		case *age.MasterKey:
			ageKeys = append(ageKeys, k.Recipient)
		default:
			return Recipients{}, errors.Errorf("%s uses unsupported key type %s", path, key.TypeToIdentifier())
		}
	}
	return NewRecipients(pgpKeys, ageKeys), nil
}

func normalizeKeys(keys []string, norm func(string) string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		k = strings.TrimSpace(k)
		if norm != nil {
			k = norm(k)
		}
		if k == "" {
			continue
		}
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
