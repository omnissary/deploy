// Package agekey wraps filippo.io/age for generating X25519 key pairs.
package agekey

import (
	"filippo.io/age"

	"git.tatikoma.dev/corpix/atlas/errors"
)

// Pair holds an age X25519 key pair as strings.
type Pair struct {
	Private string // AGE-SECRET-KEY-1...
	Public  string // age1...
}

// Generate creates a new random X25519 age key pair.
func Generate() (Pair, error) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		return Pair{}, errors.Wrap(err, "generate age x25519 identity")
	}
	return Pair{
		Private: id.String(),
		Public:  id.Recipient().String(),
	}, nil
}
