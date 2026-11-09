// Package yggdrasil handles the existing Ed25519 PKCS#8 identity format. Address
// derivation follows the protocol's inverted-public-key prefix encoding.
package yggdrasil

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"git.tatikoma.dev/corpix/atlas/errors"
	"net"
)

type Identity struct {
	Address   string `json:"address"`
	PublicKey string `json:"publicKey"`
}

func Generate() (string, error) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), nil
}
func Parse(value string) (Identity, error) {
	block, _ := pem.Decode([]byte(value))
	if block == nil {
		return Identity{}, errors.New("invalid Yggdrasil private key PEM")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return Identity{}, err
	}
	private, ok := key.(ed25519.PrivateKey)
	if !ok {
		return Identity{}, errors.New("Yggdrasil requires an Ed25519 key")
	}
	public := private.Public().(ed25519.PublicKey)
	address := make(net.IP, 16)
	address[0] = 2
	bit := func(index int) byte {
		if index >= len(public)*8 {
			return 0
		}
		return (^public[index/8] >> uint(7-index%8)) & 1
	}
	prefix := 0
	for prefix < 256 && bit(prefix) == 1 {
		prefix++
	}
	address[1] = byte(prefix)
	for i := 0; i < 112; i++ {
		address[2+i/8] |= bit(prefix+1+i) << uint(7-i%8)
	}
	return Identity{Address: address.String(), PublicKey: hex.EncodeToString(public)}, nil
}
