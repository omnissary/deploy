// Package sops wraps the getsops/sops library for encrypt/decrypt operations.
// All operations that modify files are atomic (write to tmp, then rename).
package sops

import (
	"fmt"
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

// DecryptBinary decrypts a sops binary-format file and returns plaintext bytes.
func DecryptBinary(filePath string) ([]byte, error) {
	log.Debug().Str("file", filePath).Msg("sops decrypt binary")
	storesCfg := config.NewStoresConfig()
	store := common.StoreForFormat(formats.Binary, storesCfg)

	tree, err := common.LoadEncryptedFile(store, filePath)
	if err != nil {
		return nil, errors.Wrapf(err, "sops load encrypted %s", filePath)
	}

	_, err = common.DecryptTree(common.DecryptTreeOpts{
		Tree:            tree,
		KeyServices:     keyServices(),
		DecryptionOrder: decryptionOrder(),
		Cipher:          newCipher(),
	})
	if err != nil {
		return nil, errors.Wrapf(err, "sops decrypt binary %s", filePath)
	}

	plain, err := store.EmitPlainFile(tree.Branches)
	if err != nil {
		return nil, errors.Wrap(err, "sops emit plain binary")
	}
	return plain, nil
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
	return writeNew(path, out, 0o600)
}

// DecryptYAMLExtract decrypts a YAML secrets file and returns the string value at key.
func DecryptYAMLExtract(filePath, key string) (string, error) {
	log.Debug().Str("file", filePath).Str("key", key).Msg("sops decrypt yaml extract")
	storesCfg := config.NewStoresConfig()
	store := common.StoreForFormat(formats.Yaml, storesCfg)

	tree, err := common.LoadEncryptedFile(store, filePath)
	if err != nil {
		return "", errors.Wrapf(err, "sops load encrypted %s", filePath)
	}

	_, err = common.DecryptTree(common.DecryptTreeOpts{
		Tree:            tree,
		KeyServices:     keyServices(),
		DecryptionOrder: decryptionOrder(),
		Cipher:          newCipher(),
	})
	if err != nil {
		return "", errors.Wrapf(err, "sops decrypt yaml %s", filePath)
	}

	plain, err := store.EmitPlainFile(tree.Branches)
	if err != nil {
		return "", errors.Wrap(err, "sops emit plain yaml")
	}

	var m map[string]interface{}
	if err := yaml.Unmarshal(plain, &m); err != nil {
		return "", errors.Wrap(err, "parse decrypted yaml")
	}
	v, ok := m[key]
	if !ok {
		return "", errors.Errorf("%w: %q in %s", ErrKeyNotFound, key, filePath)
	}
	return fmt.Sprintf("%v", v), nil
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

// VerifyFile checks that a SOPS-encrypted file can be decrypted and that its
// integrity metadata is valid.
func VerifyFile(filePath string) error {
	log.Debug().Str("file", filePath).Msg("sops verify file")

	storesCfg := config.NewStoresConfig()
	format := formats.FormatForPath(filePath)
	store := common.StoreForFormat(format, storesCfg)

	tree, err := common.LoadEncryptedFile(store, filePath)
	if err != nil {
		return errors.Wrapf(err, "sops load encrypted %s", filePath)
	}

	if _, err := common.DecryptTree(common.DecryptTreeOpts{
		Tree:            tree,
		KeyServices:     keyServices(),
		DecryptionOrder: decryptionOrder(),
		Cipher:          newCipher(),
	}); err != nil {
		return errors.Wrapf(err, "sops verify %s", filePath)
	}

	return nil
}

// RepairFile decrypts a SOPS-encrypted file while ignoring a stale MAC,
// reapplies the current creation rule from .sops.yaml, and writes back a fresh
// encrypted file atomically.
func RepairFile(confPath, filePath string) error {
	log.Debug().Str("file", filePath).Msg("sops repair file")

	cfg, err := config.LoadCreationRuleForFile(confPath, filePath, nil)
	if err != nil {
		return errors.Wrapf(err, "load sops creation rule for %s", filePath)
	}

	storesCfg := config.NewStoresConfig()
	format := formats.FormatForPath(filePath)
	store := common.StoreForFormat(format, storesCfg)

	tree, err := common.LoadEncryptedFile(store, filePath)
	if err != nil {
		return errors.Wrapf(err, "sops load encrypted %s", filePath)
	}

	dataKey, err := common.DecryptTree(common.DecryptTreeOpts{
		Tree:            tree,
		KeyServices:     keyServices(),
		DecryptionOrder: decryptionOrder(),
		IgnoreMac:       true,
		Cipher:          newCipher(),
	})
	if err != nil {
		return errors.Wrapf(err, "sops decrypt tree ignoring mac %s", filePath)
	}

	tree.Metadata.KeyGroups = cfg.KeyGroups
	tree.Metadata.ShamirThreshold = cfg.ShamirThreshold

	errs := tree.Metadata.UpdateMasterKeysWithKeyServices(dataKey, keyServices())
	if len(errs) > 0 {
		return errors.Wrapf(errs[0], "sops update master keys for %s", filePath)
	}

	if err := common.EncryptTree(common.EncryptTreeOpts{
		DataKey: dataKey,
		Tree:    tree,
		Cipher:  newCipher(),
	}); err != nil {
		return errors.Wrapf(err, "sops re-encrypt tree %s", filePath)
	}

	out, err := store.EmitEncryptedFile(*tree)
	if err != nil {
		return errors.Wrapf(err, "sops emit repaired file %s", filePath)
	}

	return writeAtomic(filePath, out, 0o600)
}

// DeleteYAML decrypts the file, removes the top-level key, and re-encrypts in-place.
// Returns an error wrapping ErrKeyNotFound if the key does not exist.
func DeleteYAML(filePath, key string) error {
	log.Debug().Str("file", filePath).Str("key", key).Msg("sops delete yaml key")

	store, tree, dataKey, err := loadDecrypted(filePath, formats.Yaml)
	if err != nil {
		return err
	}

	branch := tree.Branches[0]
	filtered := branch[:0:0]
	found := false
	for _, item := range branch {
		if item.Key == key {
			found = true
			continue
		}
		filtered = append(filtered, item)
	}
	if !found {
		return errors.Errorf("%w: %q in %s", ErrKeyNotFound, key, filePath)
	}
	tree.Branches[0] = filtered

	return encryptAndWrite(store, tree, dataKey, filePath)
}

// SetYAML decrypts the file, sets key=value, and re-encrypts in-place.
func SetYAML(filePath, key, value string) error {
	log.Debug().Str("file", filePath).Str("key", key).Msg("sops set yaml key")

	store, tree, dataKey, err := loadDecrypted(filePath, formats.Yaml)
	if err != nil {
		return err
	}

	tree.Branches[0], _ = tree.Branches[0].Set([]interface{}{key}, value)

	return encryptAndWrite(store, tree, dataKey, filePath)
}

// EnsureYAML sets key to the value returned by generate only if the key is
// absent. The file is decrypted exactly once, so a failed decryption can never
// be mistaken for a missing key. Returns true if the key was created.
func EnsureYAML(filePath, key string, generate func() (string, error)) (bool, error) {
	log.Debug().Str("file", filePath).Str("key", key).Msg("sops ensure yaml key")

	store, tree, dataKey, err := loadDecrypted(filePath, formats.Yaml)
	if err != nil {
		return false, err
	}

	for _, item := range tree.Branches[0] {
		if item.Key == key {
			return false, nil
		}
	}

	value, err := generate()
	if err != nil {
		return false, errors.Wrapf(err, "generate value for %s", key)
	}
	tree.Branches[0], _ = tree.Branches[0].Set([]interface{}{key}, value)

	if err := encryptAndWrite(store, tree, dataKey, filePath); err != nil {
		return false, err
	}
	return true, nil
}

func loadDecrypted(filePath string, format formats.Format) (common.Store, *gosops.Tree, []byte, error) {
	store := common.StoreForFormat(format, config.NewStoresConfig())

	tree, err := common.LoadEncryptedFile(store, filePath)
	if err != nil {
		return nil, nil, nil, errors.Wrapf(err, "sops load encrypted %s", filePath)
	}

	dataKey, err := common.DecryptTree(common.DecryptTreeOpts{
		Tree:            tree,
		KeyServices:     keyServices(),
		DecryptionOrder: decryptionOrder(),
		Cipher:          newCipher(),
	})
	if err != nil {
		return nil, nil, nil, errors.Wrapf(err, "sops decrypt tree %s", filePath)
	}
	return store, tree, dataKey, nil
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
	return writeAtomic(filePath, out, 0o600)
}

// UpdateKeys re-encrypts the data key with the current key list from .sops.yaml.
func UpdateKeys(confPath, filePath string) error {
	log.Debug().Str("file", filePath).Msg("sops update keys")

	cfg, err := config.LoadCreationRuleForFile(confPath, filePath, nil)
	if err != nil {
		return errors.Wrapf(err, "load sops creation rule for %s", filePath)
	}

	storesCfg := config.NewStoresConfig()
	format := formats.FormatForPath(filePath)
	store := common.StoreForFormat(format, storesCfg)

	tree, err := common.LoadEncryptedFile(store, filePath)
	if err != nil {
		return errors.Wrapf(err, "sops load encrypted %s", filePath)
	}

	dataKey, err := common.DecryptTree(common.DecryptTreeOpts{
		Tree:            tree,
		KeyServices:     keyServices(),
		DecryptionOrder: decryptionOrder(),
		Cipher:          newCipher(),
	})
	if err != nil {
		return errors.Wrapf(err, "sops decrypt tree %s", filePath)
	}

	tree.Metadata.KeyGroups = cfg.KeyGroups
	tree.Metadata.ShamirThreshold = cfg.ShamirThreshold

	errs := tree.Metadata.UpdateMasterKeysWithKeyServices(dataKey, keyServices())
	if len(errs) > 0 {
		return errors.Wrapf(errs[0], "sops update master keys for %s", filePath)
	}

	if err := common.EncryptTree(common.EncryptTreeOpts{
		DataKey: dataKey,
		Tree:    tree,
		Cipher:  newCipher(),
	}); err != nil {
		return errors.Wrapf(err, "sops re-encrypt tree %s", filePath)
	}

	out, err := store.EmitEncryptedFile(*tree)
	if err != nil {
		return errors.Wrap(err, "sops emit after updatekeys")
	}

	return writeAtomic(filePath, out, 0o600)
}

// writeNew atomically creates path with data, failing if path exists.
func writeNew(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return errors.Wrapf(err, "create tmp for %s", path)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return errors.Wrapf(err, "write tmp for %s", path)
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return errors.Wrapf(err, "chmod tmp for %s", path)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return errors.Wrapf(err, "sync tmp for %s", path)
	}
	if err := tmp.Close(); err != nil {
		return errors.Wrapf(err, "close tmp for %s", path)
	}
	if err := os.Link(tmp.Name(), path); err != nil {
		return errors.Wrapf(err, "create %s", path)
	}
	return nil
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return errors.Wrapf(err, "write tmp %s", tmp)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return errors.Wrapf(err, "rename %s -> %s", tmp, path)
	}
	return nil
}
