package pki

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"git.tatikoma.dev/corpix/deploy/internal/manifest"
	"git.tatikoma.dev/corpix/deploy/internal/sops"
	"git.tatikoma.dev/corpix/deploy/internal/sops/sopstest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixture(t *testing.T) Store {
	t.Helper()
	f := sopstest.NewFlake(t)
	return Store{Root: f.Dir, Conf: f.SopsConf, Now: func() time.Time { return time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC) }}
}
func leaf() manifest.Certificate {
	return manifest.Certificate{Issuer: "root", Subject: "client", Usage: []string{"clientAuth"}}
}
func TestCertificateLifecycle(t *testing.T) {
	s := fixture(t)
	if _, err := s.Create("root", manifest.Authority{Subject: "root"}); err != nil {
		t.Fatal(err)
	}
	r, err := s.Certificate("client", leaf(), "ensure", false)
	if err != nil {
		t.Fatal(err)
	}
	key := r.Key
	cert := r.Certificate
	before, _ := os.ReadFile(s.privatePath("root"))
	r, err = s.Certificate("client", leaf(), "ensure", false)
	if err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(s.privatePath("root"))
	if string(before) != string(after) || r.Certificate != cert {
		t.Fatal("ensure rewrote healthy certificate")
	}
	r, err = s.Certificate("client", leaf(), "renew", false)
	if err != nil || r.Key != key || r.Certificate == cert {
		t.Fatalf("renew: %v", err)
	}
	r, err = s.Certificate("client", leaf(), "rotate", false)
	if err != nil || r.Key == key {
		t.Fatalf("rotate: %v", err)
	}
	if err := s.Verify("root", "client", true); err != nil {
		t.Fatal(err)
	}
	public, _ := os.ReadFile(s.publicPath("root"))
	if strings.Contains(string(public), "PRIVATE KEY") {
		t.Fatal("public inventory exposed keys")
	}
	sopstest.UseIdentities(t)
	if err := s.Verify("root", "client", false); err != nil {
		t.Fatalf("public verification decrypted keys: %v", err)
	}
}
func TestIntermediateAndRotation(t *testing.T) {
	s := fixture(t)
	zero := 0
	_, err := s.Create("root", manifest.Authority{Subject: "root", PathLen: &zero})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Create("intermediate", manifest.Authority{Issuer: "root"}); err == nil {
		t.Fatal("path length constraint bypassed")
	}
	_, err = s.RotateAuthority("root")
	if err != nil {
		t.Fatal(err)
	}
	state, err := s.Public("root")
	if err != nil || state.Active != 1 || len(state.Generations) != 2 {
		t.Fatal(err, state)
	}
	if _, err := s.Activate("root", 2); err != nil {
		t.Fatal(err)
	}
	bundle, err := s.Trust([]string{"root"})
	if err != nil || strings.Count(bundle, "BEGIN CERTIFICATE") != 2 {
		t.Fatal(err)
	}
	if _, err := s.Retire("root", 2, false); err == nil {
		t.Fatal("retired active generation")
	}
}
func TestRevocationAndCRL(t *testing.T) {
	s := fixture(t)
	s.Create("root", manifest.Authority{})
	r, err := s.Certificate("client", leaf(), "issue", false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Revoke("root", "client", "", 1); err != nil {
		t.Fatal(err)
	}
	if err := s.Verify("root", "client", false); err == nil {
		t.Fatal("revocation ignored")
	}
	if _, err := s.Certificate("client", leaf(), "ensure", true); err == nil {
		t.Fatal("force restored revoked credential")
	}
	if err := s.VerifyCRL("root", 0); err != nil {
		t.Fatal(err)
	}
	state, _ := s.Public("root")
	block, _ := pem.Decode([]byte(state.CRLs[1]))
	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil || len(crl.RevokedCertificateEntries) != 1 || crl.RevokedCertificateEntries[0].SerialNumber.Text(16) != r.Serial {
		t.Fatal(err)
	}
	n := crl.Number.Int64()
	s.CRL("root", 1, 7)
	state, _ = s.Public("root")
	if state.CRLNumbers[1] <= n {
		t.Fatal("CRL number did not advance")
	}
}
func TestBundleJournalRecovery(t *testing.T) {
	s := fixture(t)
	s.Create("root", manifest.Authority{})
	state, _ := s.Load("root")
	target := manifest.Target{Name: "machine", Cert: "cert", Key: "key"}
	state.Pending = []Publication{{Target: target, Values: map[string]string{"cert": "certificate", "key": "private"}}}
	if err := s.Save(state); err == nil {
		t.Fatal("expected publication failure")
	}
	public, err := s.Public("root")
	if err != nil || !public.Incomplete {
		t.Fatal(err)
	}
	path, _ := s.TargetPath(target)
	os.MkdirAll(filepath.Dir(path), 0700)
	if err := sops.Create(s.Conf, path, []byte("{}")); err != nil {
		t.Fatal(err)
	}
	state, err = s.Open("root")
	if err != nil || len(state.Pending) != 0 {
		t.Fatal(err)
	}
	f, err := sops.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	value, _ := f.Get("key")
	if value != "private" {
		t.Fatal("bundle not recovered")
	}
}
func TestAtlasExtension(t *testing.T) {
	s := fixture(t)
	s.Create("root", manifest.Authority{})
	text := `["AGENT","READER"]`
	spec := leaf()
	spec.Extensions = []manifest.Extension{{OID: "1.3.6.1.4.1.97.116.108.97.115", UTF8: &text}}
	r, err := s.Certificate("agent", spec, "issue", false)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := ParseCert(r.Certificate)
	found := false
	for _, ext := range cert.Extensions {
		if ext.Id.String() == spec.Extensions[0].OID {
			var value string
			if _, err := asn1.Unmarshal(ext.Value, &value); err != nil || value != text {
				t.Fatal(err, value)
			}
			found = true
		}
	}
	if !found {
		t.Fatal("authorization extension missing")
	}
}
func TestCSRPolicy(t *testing.T) {
	s := fixture(t)
	s.Create("root", manifest.Authority{})
	spec := leaf()
	spec.DNS = []string{"good.example"}
	request, err := s.CreateCSR("client", spec)
	if err != nil {
		t.Fatal(err)
	}
	bad := spec
	bad.DNS = []string{"other.example"}
	if _, err := s.SignCSR("client", bad, request); err == nil {
		t.Fatal("CSR SAN policy ignored")
	}
	if _, err := s.SignCSR("client", spec, request); err != nil {
		t.Fatal(err)
	}
}
func TestCorruptionDoesNotGenerateReplacement(t *testing.T) {
	s := fixture(t)
	s.Create("root", manifest.Authority{})
	s.Certificate("client", leaf(), "issue", false)
	path := s.privatePath("root")
	os.WriteFile(path, []byte("broken"), 0600)
	before, _ := os.ReadFile(path)
	if _, err := s.Certificate("client", leaf(), "rotate", true); err == nil {
		t.Fatal("corrupt state accepted")
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("corrupt state overwritten")
	}
}

func TestDelegatedAuthorityCSR(t *testing.T) {
	s := fixture(t)
	if _, err := s.Create("root", manifest.Authority{}); err != nil {
		t.Fatal(err)
	}
	zero := 0
	policy := manifest.Authority{Issuer: "root", Subject: "delegated", PathLen: &zero}
	request, err := s.CreateAuthorityCSR("delegated", policy)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := s.SignAuthorityCSR("delegated", policy, request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ImportAuthority("delegated", policy, certificate, ""); err != nil {
		t.Fatal(err)
	}
	spec := leaf()
	spec.Issuer = "delegated"
	if _, err := s.Certificate("client", spec, "issue", false); err != nil {
		t.Fatal(err)
	}
	if err := s.Verify("delegated", "client", true); err != nil {
		t.Fatal(err)
	}
	parsed, _ := ParseCert(certificate)
	if _, err := s.Revoke("root", "", parsed.SerialNumber.Text(16), 1); err != nil {
		t.Fatal(err)
	}
	if err := s.Verify("delegated", "client", false); err == nil {
		t.Fatal("revoked intermediate accepted")
	}
	if _, err := s.Certificate("another", spec, "issue", false); err == nil {
		t.Fatal("revoked intermediate signed a certificate")
	}
}

func TestEmptyNixSANListsAreIdempotent(t *testing.T) {
	s := fixture(t)
	s.Create("root", manifest.Authority{})
	spec := leaf()
	spec.DNS = []string{}
	spec.IP = []string{}
	spec.Email = []string{}
	spec.URI = []string{}
	a, err := s.Certificate("client", spec, "ensure", false)
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.Certificate("client", spec, "ensure", false)
	if err != nil || a.Certificate != b.Certificate {
		t.Fatal("empty JSON lists caused renewal", err)
	}
}

func TestAdoptExistingCertificateChainWithoutReissue(t *testing.T) {
	s := fixture(t)
	s.Create("root", manifest.Authority{})
	spec := leaf()
	issued, err := s.Certificate("existing", spec, "issue", false)
	if err != nil {
		t.Fatal(err)
	}
	chain, err := s.Chain("root", 1)
	if err != nil {
		t.Fatal(err)
	}
	target := manifest.Target{Name: "m", Cert: "client-cert", Chain: "client-cert", Key: "client-key"}
	path, _ := s.TargetPath(target)
	os.MkdirAll(filepath.Dir(path), 0700)
	data, _ := json.Marshal(map[string]string{"client-cert": issued.Certificate + chain, "client-key": issued.Key})
	if err := sops.Create(s.Conf, path, data); err != nil {
		t.Fatal(err)
	}
	spec.Target = target
	adopted, err := s.Certificate("adopted", spec, "ensure", false)
	if err != nil {
		t.Fatal(err)
	}
	if adopted.Certificate != issued.Certificate || adopted.Key != issued.Key {
		t.Fatal("adoption changed identity")
	}
	if _, err := s.Certificate("adopted", spec, "ensure", false); err != nil {
		t.Fatal(err)
	}
	file, _ := sops.Open(path)
	value, _ := file.Get("client-cert")
	if strings.Count(value, "BEGIN CERTIFICATE") != 2 {
		t.Fatal("chain duplicated or truncated")
	}
}

func TestRevocationAppliesToAllAliasesOfAnIssuerSerial(t *testing.T) {
	s := fixture(t)
	s.Create("root", manifest.Authority{})
	spec := leaf()
	r, err := s.Certificate("one", spec, "issue", false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ImportCertificate("alias", spec, r.Certificate, r.Key); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Revoke("root", "alias", "", 1); err != nil {
		t.Fatal(err)
	}
	if err := s.Verify("root", "one", false); err == nil {
		t.Fatal("serial revocation ignored for alias")
	}
	if _, err := s.Certificate("one", spec, "ensure", false); err == nil {
		t.Fatal("revoked alias was restored")
	}
}

func TestRenewImportedAuthorityPreservesDistinguishedName(t *testing.T) {
	s := fixture(t)
	policy := manifest.Authority{Subject: "root"}
	key, err := newKey("p256")
	if err != nil {
		t.Fatal(err)
	}
	template, err := authorityTemplate(policy, s.now())
	if err != nil {
		t.Fatal(err)
	}
	template.Subject.Organization = []string{"legacy organization"}
	template.Subject.ExtraNames = []pkix.AttributeTypeAndValue{{Type: asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 1}, Value: "legacy-root"}}
	cert, err := sign(template, template, key.Public(), key, s.now())
	if err != nil {
		t.Fatal(err)
	}
	private, err := keyPEM(key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.ImportAuthority("root", policy, cert, private); err != nil {
		t.Fatal(err)
	}
	before, _ := ParseCert(cert)
	state, err := s.RenewAuthority("root")
	if err != nil {
		t.Fatal(err)
	}
	after, err := ParseCert(state.Generations[0].Certificate)
	if err != nil || !bytes.Equal(before.RawSubject, after.RawSubject) {
		t.Fatalf("renew changed imported DN: %v", err)
	}
}
