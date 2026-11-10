package manifest

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"strings"

	"git.tatikoma.dev/corpix/atlas/errors"
)

func GenerateStorageKey(format string) (string, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", err
	}
	switch format {
	case "hex":
		return hex.EncodeToString(key), nil
	case "passphrase":
		return base64.RawURLEncoding.EncodeToString(key), nil
	case "":
		return "", errors.New("pool declares no format; store its existing key explicitly")
	}
	return "", errors.Errorf("unsupported ZFS key format %q", format)
}

func StorageKeyBytes(pool Pool, value string) ([]byte, error) {
	switch pool.Format {
	case "":
		if strings.TrimSpace(value) == "" {
			return nil, errors.New("ZFS key is empty")
		}
		return []byte(value), nil
	case "hex":
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
