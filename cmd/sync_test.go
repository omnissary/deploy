package cmd

import (
	"bytes"
	"strings"
	"testing"

	"git.tatikoma.dev/corpix/deploy/internal/sops"
	"git.tatikoma.dev/corpix/deploy/internal/sops/sopstest"
)

func TestRunSyncDryRunReportsWithoutChanging(t *testing.T) {
	af := newAdminFlake(t)
	secrets := newMachineWithSecret(t, af, "m")
	second := sopstest.AddPGPKey(t)
	if err := writeGenericAdmins(af, second); err != nil {
		t.Fatal(err)
	}
	conf, data := mustRead(t, af.cfg.SopsConf), mustRead(t, secrets)

	var out bytes.Buffer
	if err := runSync(af.cfg, true, &out); err != nil {
		t.Fatalf("dry run: %v", err)
	}
	for _, want := range []string{"re-encrypt: vars/secrets/m.yaml", "re-encrypt: vars/secrets/m/openssh/ssh_host_ed25519_key"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("dry-run output lacks %q:\n%s", want, out.String())
		}
	}
	if strings.Contains(out.String(), "rules:") {
		t.Errorf("rules reported as changed although they are current:\n%s", out.String())
	}
	if string(conf) != string(mustRead(t, af.cfg.SopsConf)) || string(data) != string(mustRead(t, secrets)) {
		t.Fatal("dry run modified files")
	}

	out.Reset()
	if err := runSync(af.cfg, false, &out); err != nil {
		t.Fatalf("sync: %v", err)
	}
	if !containsFold(recipientsOf(t, secrets).PGP, second) {
		t.Fatal("sync did not apply the new admin")
	}

	out.Reset()
	if err := runSync(af.cfg, true, &out); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(out.String()) != "recipients up to date" {
		t.Fatalf("not converged:\n%s", out.String())
	}
}

func TestRunSyncDryRunNeedsNoDecryptionKey(t *testing.T) {
	af := newAdminFlake(t)
	newMachineWithSecret(t, af, "m")
	sopstest.UseIdentities(t)

	var out bytes.Buffer
	if err := runSync(af.cfg, true, &out); err != nil {
		t.Fatalf("dry run without keys: %v", err)
	}
}

func TestRunSyncFailsWithoutDecryptionKeyWhenReencryptionIsNeeded(t *testing.T) {
	af := newAdminFlake(t)
	newMachineWithSecret(t, af, "m")
	if err := writeGenericAdmins(af, sopstest.AddPGPKey(t)); err != nil {
		t.Fatal(err)
	}
	sopstest.UseIdentities(t)

	if err := runSync(af.cfg, false, &bytes.Buffer{}); err == nil {
		t.Fatal("expected failure")
	}
}

// writeGenericAdmins adds fingerprints to the generic rules only, simulating
// a .sops.yaml that is ahead of the files.
func writeGenericAdmins(af adminFlake, fingerprints ...string) error {
	m, err := loadRecipientModel(af.cfg)
	if err != nil {
		return err
	}
	m.Admins = append(m.Admins, fingerprints...)
	p, err := sops.MakePlan(af.cfg.SopsConf, af.cfg.FlakeDir, m)
	if err != nil {
		return err
	}
	p.Rekey = nil
	return sops.Apply(af.cfg.SopsConf, p, nil)
}

func TestRunSyncDryRunReportsRuleChanges(t *testing.T) {
	af := newAdminFlake(t)
	if err := ensureHostKey(af.cfg, "m"); err != nil {
		t.Fatal(err)
	}
	if err := installMachineRules(af.cfg, "ghost", mustRead(t, af.cfg.FlakeDir+"/vars/secrets/m/openssh/ssh_host_ed25519_key.pub")); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := runSync(af.cfg, true, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "rules:      .sops.yaml") {
		t.Fatalf("rule change not reported:\n%s", out.String())
	}
}
