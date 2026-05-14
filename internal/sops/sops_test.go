package sops

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func writeTestYAML(t *testing.T, raw string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "secrets.yaml")
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatalf("write test yaml: %v", err)
	}

	return path
}

func TestListYAMLKeysSkipsSOPSMetadataAndSorts(t *testing.T) {
	t.Parallel()

	path := writeTestYAML(t, `z-last: ENC[AES256_GCM,data:bbb,iv:ccc,tag:ddd,type:str]
a-first: ENC[AES256_GCM,data:eee,iv:fff,tag:ggg,type:str]
sops:
  mac: ENC[AES256_GCM,data:hhh,iv:iii,tag:jjj,type:str]
  version: 3.12.2
`)

	keys, err := ListYAMLKeys(path)
	if err != nil {
		t.Fatalf("ListYAMLKeys: %v", err)
	}

	want := []string{"a-first", "z-last"}
	if !reflect.DeepEqual(keys, want) {
		t.Fatalf("unexpected keys %v, want %v", keys, want)
	}
}

func TestListYAMLKeysReturnsEmptyForMetadataOnlyFile(t *testing.T) {
	t.Parallel()

	path := writeTestYAML(t, `sops:
  mac: ENC[AES256_GCM,data:aaa,iv:bbb,tag:ccc,type:str]
  version: 3.12.2
`)

	keys, err := ListYAMLKeys(path)
	if err != nil {
		t.Fatalf("ListYAMLKeys: %v", err)
	}

	if len(keys) != 0 {
		t.Fatalf("unexpected keys %v", keys)
	}
}

func TestListYAMLKeysRejectsMalformedYAML(t *testing.T) {
	t.Parallel()

	path := writeTestYAML(t, "not: [valid\n")

	if _, err := ListYAMLKeys(path); err == nil {
		t.Fatal("expected ListYAMLKeys to fail on malformed yaml")
	}
}
