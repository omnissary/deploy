package pki

import (
	"git.tatikoma.dev/corpix/deploy/internal/vars"
	"math/big"
	"path/filepath"
)

func (s Store) requestPath(id string) string {
	return filepath.Join(vars.AdminDir(s.Root), "pki-requests", id+".yaml")
}
func dir(path string) string  { return filepath.Dir(path) }
func newBig(n int64) *big.Int { return big.NewInt(n) }
