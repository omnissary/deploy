package manifest

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"git.tatikoma.dev/corpix/atlas/errors"
	"strings"
)

// Raw ZFS keys use base64 in YAML, decoded only at the delivery boundary.
func GenerateStorageKey(format string) (string, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", err
	}
	switch format {
	case "hex", "":
		return hex.EncodeToString(key), nil
	case "passphrase":
		return base64.RawURLEncoding.EncodeToString(key), nil
	case "raw":
		return base64.StdEncoding.EncodeToString(key), nil
	}
	return "", errors.Errorf("unsupported ZFS key format %q", format)
}
func StorageKeyBytes(pool Pool, value string) ([]byte, error) {
	switch pool.Format {
	case "raw":
		data, err := base64.StdEncoding.DecodeString(value)
		if err != nil || len(data) != 32 {
			return nil, errors.New("raw ZFS key must contain base64-encoded 32-byte material")
		}
		return data, nil
	case "hex", "":
		key, err := hex.DecodeString(strings.TrimSpace(value))
		if err != nil || len(key) != 32 {
			return nil, errors.New("hex ZFS key must be 64 hexadecimal characters")
		}
		return []byte(strings.TrimSpace(value)), nil
	case "passphrase":
		if len(value) < 8 {
			return nil, errors.New("ZFS passphrase is too short")
		}
		return []byte(value), nil
	}
	return nil, errors.New("unsupported ZFS key format")
}
