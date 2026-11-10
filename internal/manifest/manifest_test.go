package manifest

import "testing"

func TestCapabilities(t *testing.T) {
	for _, tc := range []struct {
		json string
		bad  bool
	}{
		{`{"schemaVersion":99}`, true},
		{
			`{"schemaVersion":1,"machines":{"chip":{"system":"armv7l-linux","hostKey":true,"initrdSSH":false,"installer":{"backend":"executable","attribute":"config.system.build.nandFlash"}}}}`,
			false,
		},
		{`{"schemaVersion":1,"machines":{"zfs":{"disko":true,"pools":{"rpool":{"keyPath":"/run/zfs-keys/rpool.key"}}}}}`, false},
		{`{"schemaVersion":1,"machines":{"bad":{"pools":{"rpool":{"keyPath":"relative"}}}}}`, true},
	} {
		m, err := Decode([]byte(tc.json))
		if (err != nil) != tc.bad {
			t.Fatalf("%s: %v", tc.json, err)
		}
		if v, ok := m.Machines["chip"]; ok && v.InitrdSSH {
			t.Fatal("CHIP gained initrd SSH")
		}
		if v, ok := m.Machines["zfs"]; ok && (v.Installer.Backend != "nixos-anywhere" || v.Pools["rpool"].Secret != "rpool-root-key") {
			t.Fatal(v)
		}
	}
}
