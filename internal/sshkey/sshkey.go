// Package sshkey generates and manages SSH ed25519 key pairs.
package sshkey

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os/exec"
	"strings"

	"git.tatikoma.dev/corpix/atlas/errors"
	"git.tatikoma.dev/corpix/atlas/log"
	"golang.org/x/crypto/ssh"
)

// Pair holds an ed25519 key pair.
type Pair struct {
	Private ed25519.PrivateKey
	Public  ed25519.PublicKey
}

// Generate creates a new random ed25519 key pair.
func Generate() (Pair, error) {
	log.Debug().Msg("generating ed25519 key pair")
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Pair{}, errors.Wrap(err, "generate ed25519 key")
	}
	return Pair{Private: priv, Public: pub}, nil
}

// MarshalPrivatePEM serialises the private key to OpenSSH PEM bytes (no passphrase).
func MarshalPrivatePEM(pair Pair) ([]byte, error) {
	block, err := ssh.MarshalPrivateKey(pair.Private, "")
	if err != nil {
		return nil, errors.Wrap(err, "marshal ssh private key")
	}
	var buf bytes.Buffer
	if err := pem.Encode(&buf, block); err != nil {
		return nil, errors.Wrap(err, "pem encode private key")
	}
	return buf.Bytes(), nil
}

// MarshalPublicAuthorizedKey returns the authorized_keys line for the public key.
func MarshalPublicAuthorizedKey(pair Pair, comment string) ([]byte, error) {
	sshPub, err := ssh.NewPublicKey(pair.Public)
	if err != nil {
		return nil, errors.Wrap(err, "new ssh public key")
	}
	line := bytes.TrimRight(ssh.MarshalAuthorizedKey(sshPub), "\n")
	if comment != "" {
		line = append(line, ' ')
		line = append(line, []byte(comment)...)
	}
	line = append(line, '\n')
	return line, nil
}

// VerifyPair checks that the private PEM bytes correspond to the public key line.
func VerifyPair(privPEM, pubLine []byte) error {
	signer, err := ssh.ParsePrivateKey(privPEM)
	if err != nil {
		return errors.Wrap(err, "parse private key for verification")
	}
	got := bytes.Fields(ssh.MarshalAuthorizedKey(signer.PublicKey()))
	want := bytes.Fields(pubLine)
	if len(got) < 2 || len(want) < 2 {
		return errors.New("malformed authorized key line")
	}
	if !bytes.Equal(got[1], want[1]) {
		return errors.New("public key mismatch: private and public keys do not match")
	}
	return nil
}

// ToAge derives an age recipient string from an SSH public key authorized_keys
// line by shelling out to ssh-to-age.
func ToAge(pubLine []byte) (string, error) {
	log.Debug().Msg("deriving age key via ssh-to-age")
	cmd := exec.Command("ssh-to-age")
	cmd.Stdin = bytes.NewReader(pubLine)
	var out, stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", errors.Wrapf(err, "ssh-to-age: %s", stderr.String())
	}
	return strings.TrimSpace(out.String()), nil
}
