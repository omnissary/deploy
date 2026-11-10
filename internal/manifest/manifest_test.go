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
		Pools:           map[string]Pool{"rpool": {KeyPath: "/run/keys/root", Secret: "root-key", Format: "raw"}},
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
	} {
		if _, err := Decode([]byte(data)); err == nil {
			t.Fatalf("accepted invalid policy: %s", data)
		}
	}
}

func TestStoragePolicyRequiresExplicitSecretAndFormat(t *testing.T) {
	for _, field := range []string{`"secret": "key",`, `"format": "hex",`} {
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
		if _, err := Decode([]byte(strings.Replace(document, field, "", 1))); err == nil {
			t.Fatal("accepted incomplete storage binding")
		}
	}
}
