// Package keypair provisions key pairs stored as a SOPS-encrypted private key
// next to a plaintext public key. Existing keys are never replaced.
package keypair

import (
	"bytes"
	"os"
	"path/filepath"

	"git.tatikoma.dev/corpix/atlas/errors"
	"git.tatikoma.dev/corpix/atlas/log"
	"git.tatikoma.dev/corpix/deploy/internal/atomicfile"
	"git.tatikoma.dev/corpix/deploy/internal/sops"
)

// Spec describes one key pair.
type Spec struct {
	// Generate returns a new private key and its public key.
	Generate func() (priv, pub []byte, err error)
	// Derive returns the public key for a private key, byte-identical to what
	// Generate would have returned for it.
	Derive func(priv []byte) ([]byte, error)
	// Prepare, if set, runs after generation and before anything is written,
	// e.g. to install the creation rule the private key is encrypted under.
	Prepare func(pub []byte) error
	// Name labels the pair in logs and errors, e.g. "m host key".
	Name string
	// Priv is the path of the encrypted private key, Pub of the public key.
	Priv, Pub string
}

// Result reports what Ensure did.
type Result int

const (
	// Existing means both files were present; nothing was decrypted or written.
	Existing Result = iota
	// Generated means a new pair was created.
	Generated
	// RestoredPublic means the public key was missing and was derived from
	// the existing private key.
	RestoredPublic
)

// Ensure makes sure both halves of the pair exist without ever replacing an
// existing private key:
//
//   - both present: nothing happens
//   - only the private key: the public key is derived from it
//   - only the public key: error, the private key must be restored by hand
//   - neither: a new pair is generated; the private key is written first, so
//     an interrupted run leaves a state the next run recovers from
func Ensure(confPath string, s Spec) (Result, error) {
	privExists, err := exists(s.Priv)
	if err != nil {
		return 0, err
	}
	pubExists, err := exists(s.Pub)
	if err != nil {
		return 0, err
	}

	switch {
	case privExists && pubExists:
		return Existing, nil
	case pubExists:
		return 0, errors.Errorf(
			"%s: public key %s exists but private key %s is missing; restore the private key from version control, "+
				"or delete the public key to generate a new pair (anything encrypted for the old key becomes unreadable for its owner)",
			s.Name, s.Pub, s.Priv)
	case privExists:
		return RestoredPublic, restorePublic(s)
	default:
		return Generated, generate(confPath, s)
	}
}

func restorePublic(s Spec) error {
	log.Warn().Str("key", s.Name).Str("path", s.Pub).Msg("public key missing, deriving it from the private key")
	priv, err := sops.ReadFile(s.Priv)
	if err != nil {
		return errors.Wrapf(err, "%s: decrypt private key to restore public key", s.Name)
	}
	pub, err := s.Derive(priv)
	if err != nil {
		return errors.Wrapf(err, "%s: derive public key", s.Name)
	}
	if err := atomicfile.Create(s.Pub, pub, 0o644); err != nil {
		return errors.Wrapf(err, "%s: write public key", s.Name)
	}
	return nil
}

func generate(confPath string, s Spec) error {
	log.Info().Str("key", s.Name).Msg("generating key pair")
	priv, pub, err := s.Generate()
	if err != nil {
		return errors.Wrapf(err, "%s: generate", s.Name)
	}
	derived, err := s.Derive(priv)
	if err != nil {
		return errors.Wrapf(err, "%s: derive public key", s.Name)
	}
	if !bytes.Equal(derived, pub) {
		return errors.Errorf("%s: generated public key does not match its private key", s.Name)
	}
	if s.Prepare != nil {
		if err := s.Prepare(pub); err != nil {
			return errors.Wrapf(err, "%s: prepare", s.Name)
		}
	}
	for _, p := range []string{s.Priv, s.Pub} {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return errors.Wrapf(err, "%s: create directory for %s", s.Name, p)
		}
	}
	if err := sops.Create(confPath, s.Priv, priv); err != nil {
		return errors.Wrapf(err, "%s: encrypt private key", s.Name)
	}
	if err := atomicfile.Create(s.Pub, pub, 0o644); err != nil {
		return errors.Wrapf(err, "%s: write public key", s.Name)
	}
	return nil
}

func exists(path string) (bool, error) {
	_, err := os.Lstat(path)
	switch {
	case err == nil:
		return true, nil
	case os.IsNotExist(err):
		return false, nil
	default:
		return false, errors.Wrapf(err, "stat %s", path)
	}
}
