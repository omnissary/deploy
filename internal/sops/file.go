package sops

import (
	"fmt"
	"sort"

	gosops "github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/cmd/sops/common"
	"github.com/getsops/sops/v3/cmd/sops/formats"
	"github.com/getsops/sops/v3/config"

	"git.tatikoma.dev/corpix/atlas/errors"
	"git.tatikoma.dev/corpix/atlas/log"
)

// File is a decrypted SOPS file held in memory. It is produced by a single
// decryption and written back by a single Save. A File must not be used after
// Save.
type File struct {
	path    string
	store   common.Store
	tree    *gosops.Tree
	dataKey []byte
	dirty   bool
	saved   bool
}

// Open decrypts the file at path and verifies its MAC. The format (YAML or
// binary) is derived from the file extension.
func Open(path string) (*File, error) {
	return open(path, false)
}

// OpenUnverified decrypts the file at path without checking its MAC. Only
// repair tooling should use it: a MAC mismatch means the file was modified
// outside of SOPS.
func OpenUnverified(path string) (*File, error) {
	return open(path, true)
}

func open(path string, ignoreMAC bool) (*File, error) {
	log.Debug().Str("file", path).Bool("ignore-mac", ignoreMAC).Msg("sops open")

	store := common.StoreForFormat(formats.FormatForPath(path), config.NewStoresConfig())

	tree, err := common.LoadEncryptedFile(store, path)
	if err != nil {
		return nil, errors.Wrapf(err, "sops load encrypted %s", path)
	}

	dataKey, err := common.DecryptTree(common.DecryptTreeOpts{
		Tree:            tree,
		KeyServices:     keyServices(),
		DecryptionOrder: decryptionOrder(),
		IgnoreMac:       ignoreMAC,
		Cipher:          newCipher(),
	})
	if err != nil {
		return nil, errors.Wrapf(err, "sops decrypt %s", path)
	}

	return &File{path: path, store: store, tree: tree, dataKey: dataKey}, nil
}

// Edit opens path, applies fn and saves the result if fn changed anything.
// Nothing is written when fn returns an error.
func Edit(path string, fn func(*File) error) error {
	f, err := Open(path)
	if err != nil {
		return err
	}
	if err := fn(f); err != nil {
		return err
	}
	return f.Save()
}

// Path returns the path the file was opened from.
func (f *File) Path() string {
	return f.path
}

// Keys returns the top-level keys in sorted order.
func (f *File) Keys() []string {
	keys := make([]string, 0, len(f.branch()))
	for _, item := range f.branch() {
		if key, ok := item.Key.(string); ok {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return keys
}

// Has reports whether the top-level key exists.
func (f *File) Has(key string) bool {
	_, ok := f.lookup(key)
	return ok
}

// Get returns the value of a top-level scalar key. A missing key yields an
// error wrapping ErrKeyNotFound; nested values are rejected.
func (f *File) Get(key string) (string, error) {
	v, ok := f.lookup(key)
	if !ok {
		return "", errors.Errorf("%w: %q in %s", ErrKeyNotFound, key, f.path)
	}
	switch v := v.(type) {
	case string:
		return v, nil
	case gosops.TreeBranch, []interface{}:
		return "", errors.Errorf("key %q in %s is not a scalar", key, f.path)
	default:
		return fmt.Sprint(v), nil
	}
}

// Set sets a top-level key, replacing any existing value.
func (f *File) Set(key, value string) {
	f.tree.Branches[0], _ = f.branch().Set([]interface{}{key}, value)
	f.dirty = true
}

// SetIfAbsent sets key to the value returned by generate only if the key does
// not exist yet. generate is not called for an existing key. Returns true if
// the key was created.
func (f *File) SetIfAbsent(key string, generate func() (string, error)) (bool, error) {
	if f.Has(key) {
		return false, nil
	}
	value, err := generate()
	if err != nil {
		return false, errors.Wrapf(err, "generate value for %s", key)
	}
	f.Set(key, value)
	return true, nil
}

// Delete removes a top-level key. A missing key yields an error wrapping
// ErrKeyNotFound.
func (f *File) Delete(key string) error {
	branch := f.branch()
	for i, item := range branch {
		if item.Key == key {
			f.tree.Branches[0] = append(branch[:i:i], branch[i+1:]...)
			f.dirty = true
			return nil
		}
	}
	return errors.Errorf("%w: %q in %s", ErrKeyNotFound, key, f.path)
}

// Bytes returns the decrypted plaintext in the file's own format. For binary
// files this is the original content.
func (f *File) Bytes() ([]byte, error) {
	out, err := f.store.EmitPlainFile(f.tree.Branches)
	if err != nil {
		return nil, errors.Wrapf(err, "sops emit plain %s", f.path)
	}
	return out, nil
}

// Rekey replaces the recipients with those of the .sops.yaml creation rule
// matching the file. The data key, and therefore every value, is unchanged.
func (f *File) Rekey(confPath string) error {
	cfg, err := config.LoadCreationRuleForFile(confPath, f.path, nil)
	if err != nil {
		return errors.Wrapf(err, "load sops creation rule for %s", f.path)
	}
	f.tree.Metadata.KeyGroups = cfg.KeyGroups
	f.tree.Metadata.ShamirThreshold = cfg.ShamirThreshold
	if errs := f.tree.Metadata.UpdateMasterKeysWithKeyServices(f.dataKey, keyServices()); len(errs) > 0 {
		return errors.Wrapf(errs[0], "sops update master keys for %s", f.path)
	}
	f.dirty = true
	return nil
}

// MarkDirty forces the next Save to rewrite the file, which recomputes the MAC.
func (f *File) MarkDirty() {
	f.dirty = true
}

// Save re-encrypts and atomically writes the file if anything changed.
func (f *File) Save() error {
	if f.saved {
		return errors.Errorf("sops file %s already saved", f.path)
	}
	f.saved = true
	if !f.dirty {
		return nil
	}
	log.Debug().Str("file", f.path).Msg("sops save")
	return encryptAndWrite(f.store, f.tree, f.dataKey, f.path)
}

func (f *File) branch() gosops.TreeBranch {
	return f.tree.Branches[0]
}

func (f *File) lookup(key string) (interface{}, bool) {
	for _, item := range f.branch() {
		if item.Key == key {
			return item.Value, true
		}
	}
	return nil, false
}
