// Package sops wraps the getsops/sops library for encrypt/decrypt operations.
// All operations that modify files are atomic (write to tmp, then rename).
package sops

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	gosops "github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/aes"
	"github.com/getsops/sops/v3/cmd/sops/common"
	"github.com/getsops/sops/v3/cmd/sops/formats"
	"github.com/getsops/sops/v3/config"
	"github.com/getsops/sops/v3/keyservice"
	"github.com/getsops/sops/v3/version"
	"gopkg.in/yaml.v3"

	"git.tatikoma.dev/corpix/atlas/errors"
	"git.tatikoma.dev/corpix/atlas/log"
	"git.tatikoma.dev/corpix/deploy/internal/atomicfile"
)

// ErrKeyNotFound is returned when a requested top-level key is absent from a
// successfully decrypted secrets file.
var ErrKeyNotFound = errors.New("secret key not found")

func keyServices() []keyservice.KeyServiceClient {
	return []keyservice.KeyServiceClient{keyservice.NewLocalClient()}
}

func newCipher() gosops.Cipher {
	return aes.NewCipher()
}

func decryptionOrder() []string {
	if raw := strings.TrimSpace(os.Getenv("SOPS_DECRYPTION_ORDER")); raw != "" {
		parts := strings.FieldsFunc(raw, func(r rune) bool {
			return r == ',' || r == ':' || r == ' ' || r == '\t' || r == '\n'
		})
		if len(parts) > 0 {
			return parts
		}
	}
	return append([]string{}, gosops.DefaultDecryptionOrder...)
}

// Create encrypts plaintext with the recipients of the .sops.yaml creation
// rule matching path and writes it to path. The format (YAML or binary) is
// derived from the extension. Plaintext never touches the disk, and Create
// fails without writing anything if path already exists.
func Create(confPath, path string, plaintext []byte) error {
	log.Debug().Str("file", path).Msg("sops create")

	cfg, err := config.LoadCreationRuleForFile(confPath, path, nil)
	if err != nil {
		return errors.Wrapf(err, "load sops creation rule for %s", path)
	}

	store := common.StoreForFormat(formats.FormatForPath(path), config.NewStoresConfig())
	branches, err := store.LoadPlainFile(plaintext)
	if err != nil {
		return errors.Wrapf(err, "sops load plaintext for %s", path)
	}

	absPath, err := filepath.Abs(path)
	if err != nil {
		return errors.Wrap(err, "abs path")
	}

	tree := gosops.Tree{
		Branches: branches,
		Metadata: gosops.Metadata{
			KeyGroups:       cfg.KeyGroups,
			ShamirThreshold: cfg.ShamirThreshold,
			Version:         version.Version,
		},
		FilePath: absPath,
	}

	dataKey, errs := tree.GenerateDataKeyWithKeyServices(keyServices())
	if len(errs) > 0 {
		return errors.Wrapf(errs[0], "sops generate data key for %s", path)
	}

	if err := common.EncryptTree(common.EncryptTreeOpts{
		DataKey: dataKey,
		Tree:    &tree,
		Cipher:  newCipher(),
	}); err != nil {
		return errors.Wrapf(err, "sops encrypt %s", path)
	}

	out, err := store.EmitEncryptedFile(tree)
	if err != nil {
		return errors.Wrapf(err, "sops emit %s", path)
	}
	return atomicfile.Create(path, out, 0o600)
}

// ListYAMLKeys reads an encrypted SOPS YAML file and returns its plaintext
// top-level keys in sorted order without decrypting values.
func ListYAMLKeys(filePath string) ([]string, error) {
	log.Debug().Str("file", filePath).Msg("sops list yaml keys")

	rawData, err := os.ReadFile(filePath)
	if err != nil {
		return nil, errors.Wrapf(err, "read %s", filePath)
	}

	var m map[string]interface{}
	if err := yaml.Unmarshal(rawData, &m); err != nil {
		return nil, errors.Wrap(err, "parse encrypted yaml")
	}

	keys := make([]string, 0, len(m))
	for key := range m {
		if key == "sops" {
			continue
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys, nil
}

func encryptAndWrite(store common.Store, tree *gosops.Tree, dataKey []byte, filePath string) error {
	if err := common.EncryptTree(common.EncryptTreeOpts{
		DataKey: dataKey,
		Tree:    tree,
		Cipher:  newCipher(),
	}); err != nil {
		return errors.Wrapf(err, "sops re-encrypt tree %s", filePath)
	}

	out, err := store.EmitEncryptedFile(*tree)
	if err != nil {
		return errors.Wrapf(err, "sops emit %s", filePath)
	}
	return atomicfile.Write(filePath, out, 0o600)
}

// ReadFile decrypts path, verifying its MAC, and returns the plaintext.
func ReadFile(path string) ([]byte, error) {
	f, err := Open(path)
	if err != nil {
		return nil, err
	}
	return f.Bytes()
}

// Verify checks that path decrypts and that its MAC is valid.
func Verify(path string) error {
	_, err := Open(path)
	return err
}

// UpdateKeys re-encrypts the data key of path for the recipients of the
// matching .sops.yaml creation rule. Values are unchanged.
func UpdateKeys(confPath, path string) error {
	return Edit(path, func(f *File) error {
		return f.Rekey(confPath)
	})
}

// ErrRepairDeclined is returned by Repair when accept rejects the content.
var ErrRepairDeclined = errors.New("repair declined")

// Repair re-signs a file whose MAC no longer matches. It is a no-op returning
// false for a file that verifies. Otherwise the file is decrypted without the
// MAC check and handed to accept, which decides whether the content, which may
// have been modified outside of SOPS, is trustworthy. On acceptance the
// current recipients are applied and the file is rewritten with a fresh MAC.
func Repair(confPath, path string, accept func(*File) (bool, error)) (bool, error) {
	if err := Verify(path); err == nil {
		return false, nil
	}
	f, err := OpenUnverified(path)
	if err != nil {
		return false, err
	}
	ok, err := accept(f)
	if err != nil {
		return false, err
	}
	if !ok {
		return false, errors.Wrapf(ErrRepairDeclined, "%s", path)
	}
	if err := f.Rekey(confPath); err != nil {
		return false, err
	}
	if err := f.Save(); err != nil {
		return false, err
	}
	return true, Verify(path)
}
