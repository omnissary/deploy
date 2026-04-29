// Package sops wraps the getsops/sops library for encrypt/decrypt operations.
// All operations that modify files are atomic (write to tmp, then rename).
package sops

import (
	"fmt"
	"os"
	"path/filepath"

	gosops "github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/aes"
	"github.com/getsops/sops/v3/cmd/sops/common"
	"github.com/getsops/sops/v3/cmd/sops/formats"
	"github.com/getsops/sops/v3/config"
	"github.com/getsops/sops/v3/decrypt"
	"github.com/getsops/sops/v3/keyservice"
	"github.com/getsops/sops/v3/version"
	"gopkg.in/yaml.v3"

	"git.tatikoma.dev/corpix/atlas/errors"
	"git.tatikoma.dev/corpix/atlas/log"
)

func keyServices() []keyservice.KeyServiceClient {
	return []keyservice.KeyServiceClient{keyservice.NewLocalClient()}
}

func newCipher() gosops.Cipher {
	return aes.NewCipher()
}

// EncryptBinary encrypts raw bytes as a sops binary file.
// filePath is used only for matching .sops.yaml creation rules; the file does
// not need to exist. confPath is the path to .sops.yaml.
func EncryptBinary(confPath, filePath string, plaintext []byte) ([]byte, error) {
	log.Debug().Str("file", filePath).Msg("sops encrypt binary")

	cfg, err := config.LoadCreationRuleForFile(confPath, filePath, nil)
	if err != nil {
		return nil, errors.Wrapf(err, "load sops creation rule for %s", filePath)
	}

	storesCfg := config.NewStoresConfig()
	store := common.StoreForFormat(formats.Binary, storesCfg)

	branches, err := store.LoadPlainFile(plaintext)
	if err != nil {
		return nil, errors.Wrap(err, "sops load plain binary")
	}

	absPath, err := filepath.Abs(filePath)
	if err != nil {
		return nil, errors.Wrap(err, "abs path")
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
		return nil, errors.Wrapf(errs[0], "sops generate data key for %s", filePath)
	}

	if err := common.EncryptTree(common.EncryptTreeOpts{
		DataKey: dataKey,
		Tree:    &tree,
		Cipher:  newCipher(),
	}); err != nil {
		return nil, errors.Wrap(err, "sops encrypt tree")
	}

	out, err := store.EmitEncryptedFile(tree)
	if err != nil {
		return nil, errors.Wrap(err, "sops emit encrypted binary")
	}
	return out, nil
}

// DecryptBinary decrypts a sops binary-format file and returns plaintext bytes.
func DecryptBinary(filePath string) ([]byte, error) {
	log.Debug().Str("file", filePath).Msg("sops decrypt binary")
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, errors.Wrapf(err, "read %s", filePath)
	}
	plain, err := decrypt.Data(data, "binary")
	if err != nil {
		return nil, errors.Wrapf(err, "sops decrypt binary %s", filePath)
	}
	return plain, nil
}

// EncryptYAML encrypts a plaintext YAML file in-place.
// confPath is the path to .sops.yaml.
func EncryptYAML(confPath, filePath string) error {
	log.Debug().Str("file", filePath).Msg("sops encrypt yaml")

	cfg, err := config.LoadCreationRuleForFile(confPath, filePath, nil)
	if err != nil {
		return errors.Wrapf(err, "load sops creation rule for %s", filePath)
	}

	rawData, err := os.ReadFile(filePath)
	if err != nil {
		return errors.Wrapf(err, "read %s", filePath)
	}

	storesCfg := config.NewStoresConfig()
	store := common.StoreForFormat(formats.Yaml, storesCfg)

	branches, err := store.LoadPlainFile(rawData)
	if err != nil {
		return errors.Wrap(err, "sops load plain yaml")
	}

	absPath, err := filepath.Abs(filePath)
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
		return errors.Wrapf(errs[0], "sops generate data key for %s", filePath)
	}

	if err := common.EncryptTree(common.EncryptTreeOpts{
		DataKey: dataKey,
		Tree:    &tree,
		Cipher:  newCipher(),
	}); err != nil {
		return errors.Wrap(err, "sops encrypt tree")
	}

	out, err := store.EmitEncryptedFile(tree)
	if err != nil {
		return errors.Wrap(err, "sops emit encrypted yaml")
	}

	return writeAtomic(filePath, out, 0o600)
}

// DecryptYAMLExtract decrypts a YAML secrets file and returns the string value at key.
func DecryptYAMLExtract(filePath, key string) (string, error) {
	log.Debug().Str("file", filePath).Str("key", key).Msg("sops decrypt yaml extract")
	data, err := os.ReadFile(filePath)
	if err != nil {
		return "", errors.Wrapf(err, "read %s", filePath)
	}
	plain, err := decrypt.Data(data, "yaml")
	if err != nil {
		return "", errors.Wrapf(err, "sops decrypt yaml %s", filePath)
	}
	var m map[string]interface{}
	if err := yaml.Unmarshal(plain, &m); err != nil {
		return "", errors.Wrap(err, "parse decrypted yaml")
	}
	v, ok := m[key]
	if !ok {
		return "", errors.Errorf("key %q not found in %s", key, filePath)
	}
	return fmt.Sprintf("%v", v), nil
}

// SetYAML decrypts the file, sets key=value, and re-encrypts in-place.
func SetYAML(filePath, key, value string) error {
	log.Debug().Str("file", filePath).Str("key", key).Msg("sops set yaml key")

	storesCfg := config.NewStoresConfig()
	store := common.StoreForFormat(formats.Yaml, storesCfg)

	tree, err := common.LoadEncryptedFile(store, filePath)
	if err != nil {
		return errors.Wrapf(err, "sops load encrypted %s", filePath)
	}

	dataKey, err := common.DecryptTree(common.DecryptTreeOpts{
		Tree:        tree,
		KeyServices: keyServices(),
		Cipher:      newCipher(),
	})
	if err != nil {
		return errors.Wrapf(err, "sops decrypt tree %s", filePath)
	}

	branch := tree.Branches[0]
	branch, _ = branch.Set([]interface{}{key}, value)
	tree.Branches[0] = branch

	if err := common.EncryptTree(common.EncryptTreeOpts{
		DataKey: dataKey,
		Tree:    tree,
		Cipher:  newCipher(),
	}); err != nil {
		return errors.Wrap(err, "sops re-encrypt tree")
	}

	out, err := store.EmitEncryptedFile(*tree)
	if err != nil {
		return errors.Wrap(err, "sops emit yaml")
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
		Tree:        tree,
		KeyServices: keyServices(),
		Cipher:      newCipher(),
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

	out, err := store.EmitEncryptedFile(*tree)
	if err != nil {
		return errors.Wrap(err, "sops emit after updatekeys")
	}

	return writeAtomic(filePath, out, 0o600)
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
