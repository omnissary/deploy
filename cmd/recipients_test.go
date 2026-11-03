package cmd

import (
	"strings"
	"testing"

	"git.tatikoma.dev/corpix/deploy/internal/hosts"
	"git.tatikoma.dev/corpix/deploy/internal/sops"
	"git.tatikoma.dev/corpix/deploy/internal/sops/sopstest"
	"git.tatikoma.dev/corpix/deploy/internal/vars"
)

func recipientsOf(t *testing.T, path string) sops.Recipients {
	t.Helper()
	r, err := sops.ReadRecipients(path)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func containsFold(list []string, s string) bool {
	for _, v := range list {
		if strings.EqualFold(v, s) {
			return true
		}
	}
	return false
}

func TestAddAndRemoveAdminKeyReencryptsEverything(t *testing.T) {
	af := newAdminFlake(t)
	secrets := newMachineWithSecret(t, af, "m")
	files := []string{secrets, vars.MachineHostKeyPath(af.cfg.FlakeDir, "m")}
	second := sopstest.AddPGPKey(t)

	changed, err := addAdminKey(af.cfg, second)
	if err != nil || !changed {
		t.Fatalf("addAdminKey = %v, %v", changed, err)
	}
	for _, f := range files {
		if !containsFold(recipientsOf(t, f).PGP, second) {
			t.Fatalf("%s not encrypted for new admin", f)
		}
	}

	if changed, err := addAdminKey(af.cfg, strings.ToLower(second)); err != nil || changed {
		t.Fatalf("re-adding admin = %v, %v", changed, err)
	}

	changed, err = removeAdminKey(af.cfg, second)
	if err != nil || !changed {
		t.Fatalf("removeAdminKey = %v, %v", changed, err)
	}
	for _, f := range files {
		if containsFold(recipientsOf(t, f).PGP, second) {
			t.Fatalf("%s still encrypted for removed admin", f)
		}
		if !containsFold(recipientsOf(t, f).PGP, af.pgp) {
			t.Fatalf("%s lost remaining admin", f)
		}
	}
}

func TestRemoveUnknownAdminKeyChangesNothing(t *testing.T) {
	af := newAdminFlake(t)
	conf := mustRead(t, af.cfg.SopsConf)
	changed, err := removeAdminKey(af.cfg, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")
	if err != nil || changed {
		t.Fatalf("removeAdminKey = %v, %v", changed, err)
	}
	if string(conf) != string(mustRead(t, af.cfg.SopsConf)) {
		t.Fatal(".sops.yaml modified")
	}
}

func TestRemoveLastAdminKeyIsRejected(t *testing.T) {
	af := newAdminFlake(t)
	secrets := newMachineWithSecret(t, af, "m")
	conf := mustRead(t, af.cfg.SopsConf)
	before := mustRead(t, secrets)

	if _, err := removeAdminKey(af.cfg, af.pgp); err == nil {
		t.Fatal("expected refusal")
	}
	if string(conf) != string(mustRead(t, af.cfg.SopsConf)) || string(before) != string(mustRead(t, secrets)) {
		t.Fatal("files modified")
	}
}

func TestGroupMembershipFollowsHostsFile(t *testing.T) {
	af := newAdminFlake(t)
	af.cfg.HostsFile = af.cfg.FlakeDir + "/hosts.yaml"
	if err := ensureHostKey(af.cfg, "m"); err != nil {
		t.Fatal(err)
	}
	setGroups := func(groups map[string][]string) {
		t.Helper()
		if err := hosts.Save(af.cfg.HostsFile, &hosts.File{Groups: groups}); err != nil {
			t.Fatal(err)
		}
		if err := syncAllRecipients(af.cfg); err != nil {
			t.Fatal(err)
		}
	}
	machineAgeKey := machineAge(t, af.cfg, "m")

	setGroups(map[string][]string{"g": {"m"}})
	shared := vars.SharedSecretsPath(af.cfg.FlakeDir, "g")
	if err := createEncryptedYAMLIfMissing(af.cfg, shared, "group", "g"); err != nil {
		t.Fatal(err)
	}
	if !containsFold(recipientsOf(t, shared).Age, machineAgeKey) {
		t.Fatal("member cannot read group secrets")
	}

	setGroups(map[string][]string{"g": nil})
	if containsFold(recipientsOf(t, shared).Age, machineAgeKey) {
		t.Fatal("removed member can still read group secrets")
	}
	if !containsFold(recipientsOf(t, shared).Age, af.session.Public) {
		t.Fatal("session lost access")
	}
}

func TestSyncDropsRulesOfInterruptedHostKeyGeneration(t *testing.T) {
	af := newAdminFlake(t)
	_, pub, err := sshKeyGenerator("")()
	if err != nil {
		t.Fatal(err)
	}
	if err := installMachineRules(af.cfg, "ghost", pub); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(mustRead(t, af.cfg.SopsConf)), "ghost") {
		t.Fatal("rules not installed")
	}

	if err := syncAllRecipients(af.cfg); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(mustRead(t, af.cfg.SopsConf)), "ghost") {
		t.Fatal("rules for a machine without host key survived sync")
	}
}

func TestSyncAllRecipientsIsIdempotent(t *testing.T) {
	af := newAdminFlake(t)
	secrets := newMachineWithSecret(t, af, "m")
	conf, data := mustRead(t, af.cfg.SopsConf), mustRead(t, secrets)

	if err := syncAllRecipients(af.cfg); err != nil {
		t.Fatal(err)
	}
	if string(conf) != string(mustRead(t, af.cfg.SopsConf)) || string(data) != string(mustRead(t, secrets)) {
		t.Fatal("second sync modified files")
	}
}
