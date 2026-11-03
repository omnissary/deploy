package sops

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/getsops/sops/v3/config"

	"git.tatikoma.dev/corpix/deploy/internal/sops/sopstest"
	"git.tatikoma.dev/corpix/deploy/internal/sshkey"
	"git.tatikoma.dev/corpix/deploy/internal/vars"
)

const (
	adminA = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	adminB = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
)

func regexes(rules []creationRule) []string {
	out := make([]string, len(rules))
	for i, r := range rules {
		out[i] = r.PathRegex
	}
	return out
}

func ruleFor(t *testing.T, rules []creationRule, regex string) keyGroup {
	t.Helper()
	for _, r := range rules {
		if r.PathRegex == regex {
			return r.KeyGroups[0]
		}
	}
	t.Fatalf("no rule %q", regex)
	return keyGroup{}
}

func TestDesiredRulesBaseline(t *testing.T) {
	t.Parallel()
	rules, err := DesiredRules(Model{Admins: []string{adminB, adminA}, Sessions: []string{"age1s"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := regexes(rules), []string{vars.GenericMachineRegex, vars.GenericSharedRegex, vars.AdminVarsRegex}; !reflect.DeepEqual(got, want) {
		t.Fatalf("rules = %v, want %v", got, want)
	}
	all := keyGroup{PGP: []string{adminA, adminB}, Age: []string{"age1s"}}
	for _, regex := range []string{vars.GenericMachineRegex, vars.GenericSharedRegex} {
		if got := ruleFor(t, rules, regex); !reflect.DeepEqual(got, all) {
			t.Errorf("%s = %+v, want %+v", regex, got, all)
		}
	}
	if got := ruleFor(t, rules, vars.AdminVarsRegex); len(got.Age) != 0 || !reflect.DeepEqual(got.PGP, all.PGP) {
		t.Errorf("admin rule must be PGP-only: %+v", got)
	}
}

func TestDesiredRulesMachinesGroupsAndForeignRules(t *testing.T) {
	t.Parallel()
	m := Model{
		Admins:   []string{adminA},
		Sessions: []string{"age1s"},
		Machines: map[string]string{"b": "age1b", "a": "age1a"},
		Groups:   map[string][]string{"web": {"b", "unprovisioned"}, "empty": nil},
	}
	foreign := creationRule{PathRegex: `^custom/.*$`, KeyGroups: []keyGroup{{PGP: []string{adminA}}}}
	current := []creationRule{
		{PathRegex: vars.MachineSecretsRegex("gone"), KeyGroups: []keyGroup{{PGP: []string{adminA}}}},
		{PathRegex: vars.SharedSecretsRegex("stale"), KeyGroups: []keyGroup{{PGP: []string{adminA}}}},
		foreign,
		{PathRegex: vars.GenericMachineRegex, KeyGroups: []keyGroup{{PGP: []string{adminA}}}},
	}

	rules, err := DesiredRules(m, current)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		vars.MachineVarsRegex("a"), vars.MachineVarsRegex("b"),
		vars.MachineSecretsRegex("a"), vars.MachineSecretsRegex("b"),
		vars.SharedSecretsRegex("empty"), vars.SharedSecretsRegex("web"),
		foreign.PathRegex,
		vars.GenericMachineRegex, vars.GenericSharedRegex, vars.AdminVarsRegex,
	}
	if got := regexes(rules); !reflect.DeepEqual(got, want) {
		t.Fatalf("rules =\n%v\nwant\n%v", got, want)
	}
	for _, regex := range []string{vars.MachineVarsRegex("a"), vars.MachineSecretsRegex("a")} {
		if got := ruleFor(t, rules, regex).Age; !reflect.DeepEqual(got, []string{"age1a", "age1s"}) {
			t.Errorf("%s age = %v", regex, got)
		}
	}
	if got := ruleFor(t, rules, vars.SharedSecretsRegex("web")).Age; !reflect.DeepEqual(got, []string{"age1b", "age1s"}) {
		t.Errorf("web age = %v", got)
	}
	if got := ruleFor(t, rules, vars.SharedSecretsRegex("empty")).Age; !reflect.DeepEqual(got, []string{"age1s"}) {
		t.Errorf("empty group age = %v", got)
	}
	if got := ruleFor(t, rules, foreign.PathRegex); !reflect.DeepEqual(got, foreign.KeyGroups[0]) {
		t.Errorf("foreign rule modified: %+v", got)
	}
}

func TestDesiredRulesIsIdempotent(t *testing.T) {
	t.Parallel()
	m := Model{Admins: []string{adminA}, Sessions: []string{"age1s"}, Machines: map[string]string{"a": "age1a"}, Groups: map[string][]string{"g": {"a"}}}
	first, err := DesiredRules(m, []creationRule{{PathRegex: `^x$`}})
	if err != nil {
		t.Fatal(err)
	}
	second, err := DesiredRules(m, first)
	if err != nil {
		t.Fatal(err)
	}
	if !ruleListsEqual(first, second) {
		t.Fatalf("not idempotent:\n%v\n%v", regexes(first), regexes(second))
	}
}

func TestDesiredRulesRejectsInvalidModels(t *testing.T) {
	t.Parallel()
	for name, m := range map[string]Model{
		"no admins":         {Sessions: []string{"age1s"}},
		"blank admin":       {Admins: []string{" "}},
		"reserved machine":  {Admins: []string{adminA}, Machines: map[string]string{"shared": "age1x"}},
		"traversal machine": {Admins: []string{adminA}, Machines: map[string]string{"../x": "age1x"}},
		"regex machine":     {Admins: []string{adminA}, Machines: map[string]string{"a.*": "age1x"}},
		"uppercase group":   {Admins: []string{adminA}, Groups: map[string][]string{"Web": nil}},
		"regex in group":    {Admins: []string{adminA}, Groups: map[string][]string{"a|b": nil}},
	} {
		if _, err := DesiredRules(m, nil); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestOwnedRule(t *testing.T) {
	t.Parallel()
	for regex, want := range map[string]bool{
		vars.GenericMachineRegex:        true,
		vars.GenericSharedRegex:         true,
		vars.AdminVarsRegex:             true,
		vars.MachineSecretsRegex("m-1"): true,
		vars.MachineVarsRegex("m_1"):    true,
		vars.SharedSecretsRegex("g"):    true,
		vars.GenericHostKeyRegex:        false,
		vars.GenericInitrdRegex:         false,
		`^custom/.*$`:                   false,
		`vars/secrets/a.*\.yaml$`:       false,
		`vars/secrets/a/b\.yaml$`:       false,
	} {
		if got := ownedRule(regex); got != want {
			t.Errorf("ownedRule(%q) = %v, want %v", regex, got, want)
		}
	}
}

func TestMatchRuleAgreesWithSops(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	conf := filepath.Join(dir, ".sops.yaml")
	m := Model{
		Admins:   []string{adminA},
		Sessions: []string{sopstest.NewIdentity(t).Public},
		Machines: map[string]string{"web": sopstest.NewIdentity(t).Public},
		Groups:   map[string][]string{"edge": {"web"}},
	}
	rules, err := DesiredRules(m, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeSopsYAML(conf, sopsYAML{CreationRules: rules}); err != nil {
		t.Fatal(err)
	}
	for _, rel := range []string{
		"vars/secrets/web.yaml",
		"vars/secrets/other.yaml",
		"vars/secrets/web/openssh/ssh_host_ed25519_key",
		"vars/secrets/shared/edge.yaml",
		"vars/secrets/shared/unknown.yaml",
		"vars/admin/session-age-key",
	} {
		path := filepath.Join(dir, rel)
		ours, err := matchRule(rules, dir, path)
		if err != nil {
			t.Fatalf("%s: %v", rel, err)
		}
		theirs, err := config.LoadCreationRuleForFile(conf, path, nil)
		if err != nil {
			t.Fatalf("%s: sops: %v", rel, err)
		}
		var theirAge, theirPGP []string
		for _, k := range theirs.KeyGroups[0] {
			id := k.ToString()
			if strings.HasPrefix(id, "age1") {
				theirAge = append(theirAge, id)
			} else {
				theirPGP = append(theirPGP, id)
			}
		}
		want := NewRecipients(theirPGP, theirAge)
		if got := NewRecipients(ours.KeyGroups[0].PGP, ours.KeyGroups[0].Age); !got.Equal(want) {
			t.Errorf("%s: matchRule picked %+v, sops picked %+v", rel, got, want)
		}
	}
	if _, err := matchRule(rules, dir, filepath.Join(dir, "vars/secrets/nobody/openssh/ssh_host_ed25519_key")); err == nil {
		t.Error("expected no rule for a machine outside the model")
	}
}

type syncFixture struct {
	dir, conf string
	model     Model
	session   sopstest.Identity
}

func newSyncFixture(t *testing.T) *syncFixture {
	t.Helper()
	session := sopstest.NewIdentity(t)
	sopstest.UseIdentities(t, session)
	pgp := sopstest.NewPGPKey(t)
	dir := t.TempDir()
	f := &syncFixture{
		dir:     dir,
		conf:    filepath.Join(dir, ".sops.yaml"),
		model:   Model{Admins: []string{pgp}, Sessions: []string{session.Public}, Machines: map[string]string{}, Groups: map[string][]string{}},
		session: session,
	}
	if err := InitConf(f.conf, []string{pgp}); err != nil {
		t.Fatal(err)
	}
	f.sync(t)
	return f
}

func (f *syncFixture) sync(t *testing.T) Plan {
	t.Helper()
	p, err := Sync(f.conf, f.dir, f.model, UpdateKeys)
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	return p
}

func (f *syncFixture) plan(t *testing.T) Plan {
	t.Helper()
	p, err := MakePlan(f.conf, f.dir, f.model)
	if err != nil {
		t.Fatalf("MakePlan: %v", err)
	}
	return p
}

func (f *syncFixture) create(t *testing.T, path string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := Create(f.conf, path, []byte("k: v\n")); err != nil {
		t.Fatal(err)
	}
	return path
}

func canRead(t *testing.T, id sopstest.Identity, path string) bool {
	t.Helper()
	gnupg := os.Getenv("GNUPGHOME")
	defer t.Setenv("GNUPGHOME", gnupg)
	defer t.Setenv("SOPS_AGE_KEY", os.Getenv("SOPS_AGE_KEY"))
	sopstest.UseIdentities(t, id)
	return Verify(path) == nil
}

func TestSyncFreshFlakeIsStable(t *testing.T) {
	f := newSyncFixture(t)
	if p := f.plan(t); !p.Empty() {
		t.Fatalf("plan after sync not empty: %+v", p)
	}
}

func TestSyncAddingMachineRekeysItsExistingSecrets(t *testing.T) {
	f := newSyncFixture(t)
	secrets := f.create(t, vars.MachineSecretsPath(f.dir, "web"))
	other := f.create(t, vars.MachineSecretsPath(f.dir, "db"))
	machine := sopstest.NewIdentity(t)
	f.model.Machines["web"] = machine.Public

	p := f.plan(t)
	if !p.RulesChanged || !reflect.DeepEqual(p.Rekey, []string{secrets}) {
		t.Fatalf("plan = %+v", p)
	}
	f.sync(t)

	if !canRead(t, machine, secrets) {
		t.Fatal("machine cannot read its secrets")
	}
	if canRead(t, machine, other) {
		t.Fatal("machine can read another machine's secrets")
	}
	if !canRead(t, f.session, secrets) {
		t.Fatal("session lost access")
	}
	if p := f.plan(t); !p.Empty() {
		t.Fatalf("not converged: %+v", p)
	}
}

func TestSyncRemovingSessionRevokesAccess(t *testing.T) {
	f := newSyncFixture(t)
	second := sopstest.NewIdentity(t)
	f.model.Sessions = append(f.model.Sessions, second.Public)
	f.sync(t)
	files := []string{
		f.create(t, vars.MachineSecretsPath(f.dir, "a")),
		f.create(t, vars.SharedSecretsPath(f.dir, "g")),
	}
	admin := f.create(t, filepath.Join(vars.AdminDir(f.dir), "thing"))
	for _, p := range files {
		if !canRead(t, second, p) {
			t.Fatalf("second session cannot read %s", p)
		}
	}
	if canRead(t, second, admin) {
		t.Fatal("session can read vars/admin")
	}

	f.model.Sessions = f.model.Sessions[:1]
	f.sync(t)
	for _, p := range files {
		if canRead(t, second, p) {
			t.Fatalf("removed session can still read %s", p)
		}
		if !canRead(t, f.session, p) {
			t.Fatalf("remaining session lost %s", p)
		}
	}
}

func TestSyncGroupMembership(t *testing.T) {
	f := newSyncFixture(t)
	a, b := sopstest.NewIdentity(t), sopstest.NewIdentity(t)
	f.model.Machines["a"], f.model.Machines["b"] = a.Public, b.Public
	f.model.Groups["g"] = []string{"a"}
	f.sync(t)
	shared := f.create(t, vars.SharedSecretsPath(f.dir, "g"))
	if !canRead(t, a, shared) || canRead(t, b, shared) {
		t.Fatal("initial membership wrong")
	}

	f.model.Groups["g"] = []string{"b"}
	f.sync(t)
	if canRead(t, a, shared) || !canRead(t, b, shared) {
		t.Fatal("membership change not applied")
	}

	delete(f.model.Groups, "g")
	f.sync(t)
	if canRead(t, b, shared) {
		t.Fatal("dropped group still grants member access")
	}
	if !canRead(t, f.session, shared) {
		t.Fatal("session lost access to a dropped group's file")
	}
}

func TestMakePlanDetectsDriftWithUnchangedRules(t *testing.T) {
	f := newSyncFixture(t)
	path := f.create(t, vars.MachineSecretsPath(f.dir, "a"))
	machine := sopstest.NewIdentity(t)
	f.model.Machines["a"] = machine.Public
	p := f.plan(t)
	if err := Apply(f.conf, Plan{Rules: p.Rules, RulesChanged: true}, UpdateKeys); err != nil {
		t.Fatal(err)
	}

	p = f.plan(t)
	if p.RulesChanged || !reflect.DeepEqual(p.Rekey, []string{path}) {
		t.Fatalf("drift not detected: %+v", p)
	}
}

func TestSyncRecoversFromPartialFailure(t *testing.T) {
	f := newSyncFixture(t)
	a := f.create(t, vars.MachineSecretsPath(f.dir, "a"))
	b := f.create(t, vars.MachineSecretsPath(f.dir, "b"))
	f.model.Sessions = append(f.model.Sessions, sopstest.NewIdentity(t).Public)

	boom := errors.New("boom")
	calls := 0
	_, err := Sync(f.conf, f.dir, f.model, func(conf, path string) error {
		calls++
		if calls == 2 {
			return boom
		}
		return UpdateKeys(conf, path)
	})
	if !errors.Is(err, boom) {
		t.Fatalf("expected failure, got %v", err)
	}
	p := f.plan(t)
	if p.RulesChanged || len(p.Rekey) != 1 {
		t.Fatalf("remaining plan = %+v", p)
	}
	f.sync(t)
	if p := f.plan(t); !p.Empty() {
		t.Fatalf("not converged: %+v", p)
	}
	for _, path := range []string{a, b} {
		if err := Verify(path); err != nil {
			t.Fatal(err)
		}
	}
}

func TestMakePlanFailsForFileWithoutRule(t *testing.T) {
	f := newSyncFixture(t)
	orphan := vars.MachineHostKeyPath(f.dir, "ghost")
	if err := os.MkdirAll(filepath.Dir(orphan), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(orphan, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := MakePlan(f.conf, f.dir, f.model)
	if err == nil || !strings.Contains(err.Error(), orphan) {
		t.Fatalf("expected error naming %s, got %v", orphan, err)
	}
}

func TestMakePlanNeedsNoDecryptionKeys(t *testing.T) {
	f := newSyncFixture(t)
	f.create(t, vars.MachineSecretsPath(f.dir, "a"))
	f.model.Sessions = append(f.model.Sessions, sopstest.NewIdentity(t).Public)
	sopstest.UseIdentities(t)

	p, err := MakePlan(f.conf, f.dir, f.model)
	if err != nil {
		t.Fatalf("MakePlan: %v", err)
	}
	if len(p.Rekey) != 1 {
		t.Fatalf("plan = %+v", p)
	}
}

func TestLoadModel(t *testing.T) {
	if _, err := exec.LookPath("ssh-to-age"); err != nil {
		t.Skip("ssh-to-age not in PATH")
	}
	t.Parallel()
	dir := t.TempDir()
	conf := filepath.Join(dir, ".sops.yaml")
	if err := InitConf(conf, []string{adminA}); err != nil {
		t.Fatal(err)
	}
	rules, err := DesiredRules(Model{Admins: []string{adminA}, Sessions: []string{"age1session"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeSopsYAML(conf, sopsYAML{CreationRules: rules}); err != nil {
		t.Fatal(err)
	}
	pair, err := sshkey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := sshkey.MarshalPublicAuthorizedKey(pair, "")
	if err != nil {
		t.Fatal(err)
	}
	pubPath := vars.MachineHostKeyPubPath(dir, "web")
	if err := os.MkdirAll(filepath.Dir(pubPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pubPath, pub, 0o644); err != nil {
		t.Fatal(err)
	}
	wantAge, err := sshkey.ToAge(pub)
	if err != nil {
		t.Fatal(err)
	}
	groups := map[string][]string{"g": {"web"}}

	m, err := LoadModel(conf, dir, groups)
	if err != nil {
		t.Fatal(err)
	}
	want := Model{Admins: []string{adminA}, Sessions: []string{"age1session"}, Machines: map[string]string{"web": wantAge}, Groups: groups}
	if !reflect.DeepEqual(m, want) {
		t.Fatalf("model = %+v, want %+v", m, want)
	}
}

func TestLoadModelRejectsBrokenInputs(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	conf := filepath.Join(dir, ".sops.yaml")
	if _, err := LoadModel(conf, dir, nil); err == nil {
		t.Fatal("accepted missing .sops.yaml")
	}
	if err := os.WriteFile(conf, []byte("creation_rules: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadModel(conf, dir, nil); err == nil {
		t.Fatal("accepted .sops.yaml without generic rule")
	}
	if err := os.Remove(conf); err != nil {
		t.Fatal(err)
	}
	if err := InitConf(conf, []string{adminA}); err != nil {
		t.Fatal(err)
	}
	pubPath := vars.MachineHostKeyPubPath(dir, "web")
	if err := os.MkdirAll(filepath.Dir(pubPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pubPath, []byte("garbage\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadModel(conf, dir, nil); err == nil {
		t.Fatal("accepted unparsable host public key")
	}
}
