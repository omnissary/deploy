package yggdrasil

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestYggdrasilCompatibility(t *testing.T) {
	value, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	identity, err := Parse(value)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := exec.LookPath("yggdrasil"); err != nil {
		t.Skip("Yggdrasil CLI unavailable for cross-check")
	}
	dir := t.TempDir()
	key := filepath.Join(dir, "key.pem")
	os.WriteFile(key, []byte(value), 0600)
	data, _ := json.Marshal(map[string]string{"PrivateKeyPath": key})
	conf := filepath.Join(dir, "conf.json")
	os.WriteFile(conf, data, 0600)
	for flag, want := range map[string]string{"-address": identity.Address, "-publickey": identity.PublicKey} {
		out, err := exec.Command("yggdrasil", "-useconffile", conf, flag).CombinedOutput()
		if err != nil || strings.TrimSpace(string(out)) != want {
			t.Fatalf("%s: %v %s != %s", flag, err, out, want)
		}
	}
}
