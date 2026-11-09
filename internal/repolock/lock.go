// Package repolock serializes deploy mutations across processes on this controller.
package repolock

import (
	"crypto/sha256"
	"fmt"
	"git.tatikoma.dev/corpix/atlas/errors"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
)

func Acquire(root string) (func(), error) {
	absolute, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	if p, e := filepath.EvalSymlinks(absolute); e == nil {
		absolute = p
	}
	directory := filepath.Join(os.TempDir(), fmt.Sprintf("deploy-locks-%d", os.Getuid()))
	if err := os.MkdirAll(directory, 0700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode().Perm() != 0700 {
		return nil, errors.New("unsafe deploy lock directory")
	}
	var ds unix.Stat_t
	if err := unix.Stat(directory, &ds); err != nil {
		return nil, err
	}
	if int(ds.Uid) != os.Getuid() {
		return nil, errors.New("deploy lock directory has another owner")
	}
	path := filepath.Join(directory, fmt.Sprintf("%x.lock", sha256.Sum256([]byte(absolute))))
	fd, err := unix.Open(path, unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		unix.Close(fd)
		return nil, errors.New("another deploy mutation is running for this repository")
	}
	return func() { unix.Flock(fd, unix.LOCK_UN); unix.Close(fd) }, nil
}
