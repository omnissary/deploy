package cmd

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"git.tatikoma.dev/corpix/deploy/internal/sops"
	"git.tatikoma.dev/corpix/deploy/internal/sops/sopstest"
	"git.tatikoma.dev/corpix/deploy/internal/vars"
)

func newMachineSecrets(t *testing.T, fl sopstest.Flake, machine string, values map[string]string) string {
	t.Helper()
	path := vars.MachineSecretsPath(fl.Dir, machine)
	if err := createEncryptedYAMLIfMissing(newTestConfig(fl), path, "machine", machine); err != nil {
		t.Fatal(err)
	}
	seedSecrets(t, path, values)
	return path
}

func tamperSecrets(t *testing.T, path, dropKey string) {
	t.Helper()
	var doc map[string]interface{}
	if err := yaml.Unmarshal([]byte(fileBytes(t, path)), &doc); err != nil {
		t.Fatal(err)
	}
	delete(doc, dropKey)
	out, err := yaml.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyAllSecretsPassesForIntactFiles(t *testing.T) {
	fl := sopstest.NewFlake(t)
	newMachineSecrets(t, fl, "a", map[string]string{"k": "v"})
	newMachineSecrets(t, fl, "b", map[string]string{"k": "v"})

	if err := verifyAllSecrets(newTestConfig(fl)); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestVerifyAllSecretsWithoutFiles(t *testing.T) {
	fl := sopstest.NewFlake(t)
	if err := verifyAllSecrets(newTestConfig(fl)); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestVerifyAllSecretsReportsEveryFailure(t *testing.T) {
	fl := sopstest.NewFlake(t)
	a := newMachineSecrets(t, fl, "a", map[string]string{"k": "v", "x": "y"})
	newMachineSecrets(t, fl, "b", map[string]string{"k": "v"})
	c := newMachineSecrets(t, fl, "c", map[string]string{"k": "v", "x": "y"})
	tamperSecrets(t, a, "x")
	tamperSecrets(t, c, "x")

	err := verifyAllSecrets(newTestConfig(fl))
	if err == nil {
		t.Fatal("expected verification failure")
	}
	msg := err.Error()
	if !strings.Contains(msg, a) || !strings.Contains(msg, c) || !strings.Contains(msg, "2 of 3") {
		t.Fatalf("error does not list every failed file: %v", err)
	}
}

func TestVerifyFilesFailsWithoutIdentity(t *testing.T) {
	fl := sopstest.NewFlake(t)
	path := newMachineSecrets(t, fl, "a", map[string]string{"k": "v"})
	sopstest.UseIdentities(t)

	if err := verifyFiles([]string{path}); err == nil {
		t.Fatal("expected failure without identity")
	}
}

func TestRepairSecretFileAccepted(t *testing.T) {
	fl := sopstest.NewFlake(t)
	path := newMachineSecrets(t, fl, "a", map[string]string{"k": "v", "x": "y"})
	tamperSecrets(t, path, "x")

	var prompt bytes.Buffer
	if err := repairSecretFile(newTestConfig(fl), path, promptRepair(strings.NewReader("y\n"), &prompt)); err != nil {
		t.Fatalf("repair: %v", err)
	}
	if err := sops.Verify(path); err != nil {
		t.Fatalf("not repaired: %v", err)
	}
	if !strings.Contains(prompt.String(), "  k\n") {
		t.Fatalf("prompt does not list the decrypted keys:\n%s", prompt.String())
	}
}

func TestRepairSecretFileDeclinedLeavesFileUntouched(t *testing.T) {
	for _, answer := range []string{"\n", "n\n", "no\n", "", "maybe\n"} {
		t.Run(strings.TrimSpace(answer), func(t *testing.T) {
			fl := sopstest.NewFlake(t)
			path := newMachineSecrets(t, fl, "a", map[string]string{"k": "v", "x": "y"})
			tamperSecrets(t, path, "x")
			before := fileBytes(t, path)

			err := repairSecretFile(newTestConfig(fl), path, promptRepair(strings.NewReader(answer), &bytes.Buffer{}))
			if !errors.Is(err, sops.ErrRepairDeclined) {
				t.Fatalf("expected ErrRepairDeclined, got %v", err)
			}
			if fileBytes(t, path) != before {
				t.Fatal("file modified")
			}
		})
	}
}

func TestRepairSecretFileOnValidFileDoesNotPrompt(t *testing.T) {
	fl := sopstest.NewFlake(t)
	path := newMachineSecrets(t, fl, "a", map[string]string{"k": "v"})
	before := fileBytes(t, path)

	var prompt bytes.Buffer
	if err := repairSecretFile(newTestConfig(fl), path, promptRepair(strings.NewReader("y\n"), &prompt)); err != nil {
		t.Fatal(err)
	}
	if prompt.Len() != 0 {
		t.Fatalf("prompted for a valid file: %q", prompt.String())
	}
	if fileBytes(t, path) != before {
		t.Fatal("file modified")
	}
}

func TestPromptRepairAcceptsYesVariants(t *testing.T) {
	fl := sopstest.NewFlake(t)
	path := newMachineSecrets(t, fl, "a", map[string]string{"k": "v"})
	f, err := sops.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, answer := range []string{"y\n", "Y\n", "yes\n", " YES \n", "y"} {
		ok, err := promptRepair(strings.NewReader(answer), &bytes.Buffer{})(f)
		if err != nil || !ok {
			t.Errorf("answer %q: got %v, %v", answer, ok, err)
		}
	}
}
