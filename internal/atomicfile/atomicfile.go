// Package atomicfile writes files so that readers observe either the old or
// the new content, never a partial write.
package atomicfile

import (
	"os"
	"path/filepath"

	"git.tatikoma.dev/corpix/atlas/errors"
)

// Write atomically replaces path with data.
func Write(path string, data []byte, mode os.FileMode) error {
	tmp, err := writeTemp(path, data, mode)
	if err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return errors.Wrapf(err, "rename %s", path)
	}
	syncDir(path)
	return nil
}

// Create atomically creates path with data. It fails with an error wrapping
// os.ErrExist, without touching the file, if path already exists.
func Create(path string, data []byte, mode os.FileMode) error {
	tmp, err := writeTemp(path, data, mode)
	if err != nil {
		return err
	}
	defer os.Remove(tmp)
	if err := os.Link(tmp, path); err != nil {
		return errors.Wrapf(err, "create %s", path)
	}
	syncDir(path)
	return nil
}

func writeTemp(path string, data []byte, mode os.FileMode) (string, error) {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return "", errors.Wrapf(err, "create tmp for %s", path)
	}
	name := f.Name()
	fail := func(err error, msg string) (string, error) {
		_ = f.Close()
		_ = os.Remove(name)
		return "", errors.Wrapf(err, "%s for %s", msg, path)
	}
	if _, err := f.Write(data); err != nil {
		return fail(err, "write tmp")
	}
	if err := f.Chmod(mode); err != nil {
		return fail(err, "chmod tmp")
	}
	if err := f.Sync(); err != nil {
		return fail(err, "sync tmp")
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(name)
		return "", errors.Wrapf(err, "close tmp for %s", path)
	}
	return name, nil
}

func syncDir(path string) {
	if d, err := os.Open(filepath.Dir(path)); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
}
