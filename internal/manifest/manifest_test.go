package manifest

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPolicyContract(t *testing.T) {
	machine := Machine{
		System:          "x86_64-linux",
		HostKey:         true,
		InitrdSSH:       true,
		InitrdPort:      6666,
		Unlock:          "zfs",
		Pools:           map[string]Pool{"rpool": {KeyPath: "/run/keys/root", Secret: "root-key", Format: "passphrase"}},
		RequiredSecrets: []SecretRef{{Name: "service", Group: true, Key: "client-cert"}},
	}
	policy := Manifest{SchemaVersion: Version, Machines: map[string]Machine{"server": machine}}
	data, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Machines["server"].Pools["rpool"].Secret != "root-key" {
		t.Fatal("explicit storage binding changed")
	}
}

func TestRejectUnsupportedPolicies(t *testing.T) {
	for _, data := range []string{
		`{"schemaVersion":1}`,
		`{"schemaVersion":2,"machines":{"node":{"system":"x86_64-linux","yggdrasil":true}}}`,
		`{"schemaVersion":2,"machines":{"node":{}}}`,
		`{"schemaVersion":2,"machines":{"node":{"system":"x86_64-linux","unlock":"zfs"}}}`,
		`{
  "schemaVersion": 2,
  "machines": {
    "node": {
      "system": "x86_64-linux",
      "pools": {
        "rpool": {
          "keyPath": "relative",
          "secret": "key",
          "format": "hex"
        }
      }
    }
  }
}`,
		`{"schemaVersion":2,"authorities":{"root":{"source":{"name":"old"}}}}`,
		`{"schemaVersion":2} {}`,
		`{"schemaVersion":2,"certificates":{"leaf":{"issuer":"root","target":{"name":"node","cert":"tls","chain":"tls","key":"tls-key"}}}}`,
		`{"schemaVersion":2,"authorities":{"root":{"target":{"name":"node","cert":"ca","ca":"ca"}}}}`,
	} {
		if _, err := Decode([]byte(data)); err == nil {
			t.Fatalf("accepted invalid policy: %s", data)
		}
	}
}

func TestStoragePolicyFormatIsOptional(t *testing.T) {
	document := `{
  "schemaVersion": 2,
  "machines": {
    "node": {
      "system": "x86_64-linux",
      "pools": {
        "rpool": {
          "secret": "key",
          "format": "hex",
          "keyPath": "/run/key"
        }
      }
    }
  }
}`
	if _, err := Decode([]byte(strings.Replace(document, `"secret": "key",`, "", 1))); err == nil {
		t.Fatal("accepted pool without secret")
	}
	if _, err := Decode([]byte(strings.Replace(document, `"format": "hex",`, `"format": "raw",`, 1))); err == nil {
		t.Fatal("accepted unsupported pool format")
	}
	m, err := Decode([]byte(strings.Replace(document, `"format": "hex",`, "", 1)))
	if err != nil {
		t.Fatal(err)
	}
	pool := m.Machines["node"].Pools["rpool"]
	if _, err := GenerateStorageKey(pool.Format); err == nil {
		t.Fatal("generated a key for a pool without format")
	}
	if _, err := StorageKeyBytes(pool, " \n"); err == nil {
		t.Fatal("accepted empty key")
	}
	value := "short-passphrase\n"
	key, err := StorageKeyBytes(pool, value)
	if err != nil || string(key) != value {
		t.Fatalf("key not delivered as stored: %q %v", key, err)
	}
}
