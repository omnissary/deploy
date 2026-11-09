package pki

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"git.tatikoma.dev/corpix/atlas/errors"
	"git.tatikoma.dev/corpix/deploy/internal/manifest"
	"git.tatikoma.dev/corpix/deploy/internal/sops"
	"math/big"
	"net"
	"os"
	"reflect"
	"slices"
	"strings"
)

func current(state *State, id string) *Record {
	for i := len(state.Records) - 1; i >= 0; i-- {
		if state.Records[i].ID == id {
			return &state.Records[i]
		}
	}
	return nil
}
func (s Store) targetMaterial(t manifest.Target) (cert, key string, err error) {
	if t.Name == "" {
		return "", "", nil
	}
	path, err := s.TargetPath(t)
	if err != nil {
		return "", "", err
	}
	file, err := sops.Open(path)
	if err != nil {
		return "", "", err
	}
	if t.Cert == "" && t.Chain != "" {
		t.Cert = t.Chain
	}
	if t.Cert != "" && file.Has(t.Cert) {
		cert, err = file.Get(t.Cert)
		if err != nil {
			return "", "", err
		}
	}
	if t.Key != "" && file.Has(t.Key) {
		key, err = file.Get(t.Key)
	}
	if cert != "" {
		parsed, e := ParseCert(cert)
		if e != nil {
			return "", "", e
		}
		cert = certPEM(parsed.Raw)
	}
	return cert, key, err
}
func (s Store) PublishRecord(state *State, r Record) error {
	if r.Spec.Target.Name == "" {
		return nil
	}
	if r.Key == "" && r.Spec.Target.Key != "" {
		return errors.New("external CSR certificate has no local private key to publish")
	}
	chain, err := s.Chain(state.ID, r.Generation)
	if err != nil {
		return err
	}
	values := map[string]string{}
	t := r.Spec.Target
	if t.Cert != "" {
		values[t.Cert] = r.Certificate
	}
	if t.Key != "" {
		values[t.Key] = r.Key
	}
	if t.Chain != "" {
		values[t.Chain] = r.Certificate + chain
	}
	if t.CA != "" {
		values[t.CA] = chain
	}
	path, err := s.TargetPath(t)
	if err != nil {
		return err
	}
	file, err := sops.Open(path)
	if err != nil {
		return err
	}
	same := true
	for k, v := range values {
		existing, e := file.Get(k)
		if e != nil || existing != v {
			same = false
		}
	}
	if same {
		return nil
	}
	state.Pending = append(state.Pending, Publication{Target: t, Values: values})
	return nil
}
func (s Store) Certificate(id string, spec manifest.Certificate, operation string, force bool) (*Record, error) {
	if err := validID(id); err != nil {
		return nil, err
	}
	state, err := s.Open(spec.Issuer)
	if err != nil {
		return nil, err
	}
	g, err := generation(state, state.Active)
	if err != nil {
		return nil, err
	}
	if err := s.checkIssuer(state.ID, g.ID, map[string]bool{}); err != nil {
		return nil, err
	}
	if g.Retired {
		return nil, errors.New("issuer generation retired")
	}
	old := current(state, id)
	adopted := false
	var key crypto.Signer
	if old == nil {
		certificate, private, err := s.targetMaterial(spec.Target)
		if err != nil {
			return nil, err
		}
		if certificate != "" && private == "" {
			return nil, errors.New("certificate exists but private key is missing; refusing replacement")
		}
		if private != "" {
			key, err = ParseKey(private)
			if err != nil {
				return nil, err
			}
			if certificate != "" {
				cert, err := ParseCert(certificate)
				if err != nil {
					return nil, err
				}
				if err := matchKey(cert, key); err != nil {
					return nil, err
				}
				for _, candidate := range state.Generations {
					issuer, err := ParseCert(candidate.Certificate)
					if err != nil {
						return nil, err
					}
					if cert.CheckSignatureFrom(issuer) == nil {
						record := Record{ID: id, Generation: candidate.ID, Serial: cert.SerialNumber.Text(16), Certificate: certificate, Key: private, Spec: spec}
						state.Records = append(state.Records, record)
						old = current(state, id)
						adopted = true
						break
					}
				}
				if old == nil {
					return nil, errors.New("existing certificate is not signed by any known issuer generation")
				}
			}
		}
	}
	if old != nil && spec.Target.Name != "" {
		certificate, private, err := s.targetMaterial(spec.Target)
		if err != nil {
			return nil, err
		}
		if certificate != "" && private == "" {
			return nil, errors.New("target certificate exists but its private key is missing")
		}
		if private != "" {
			targetKey, err := ParseKey(private)
			if err != nil {
				return nil, err
			}
			oldCert, err := ParseCert(old.Certificate)
			if err != nil {
				return nil, err
			}
			if err := matchKey(oldCert, targetKey); err != nil {
				return nil, errors.New("target private key differs from managed certificate; explicit import required")
			}
		}
		if certificate != "" && certificate != old.Certificate {
			return nil, errors.New("target certificate differs from managed inventory; explicit import required")
		}
	}
	if old != nil {
		for _, rev := range state.Revocations {
			if rev.Generation == old.Generation && rev.Serial == old.Serial {
				when := rev.Time
				old.RevokedAt = &when
				old.Reason = rev.Reason
			}
		}
	}
	if old != nil {
		if old.RevokedAt != nil && operation != "rotate" {
			return nil, errors.New("certificate is revoked; explicit rotation is required")
		}
		if operation == "issue" {
			return nil, errors.New("certificate already exists; use ensure, renew or rotate")
		}
		if old.Key == "" {
			return nil, errors.New("external certificate requires a new CSR")
		}
		key, err = ParseKey(old.Key)
		if err != nil {
			return nil, err
		}
		cert, err := ParseCert(old.Certificate)
		if err != nil {
			return nil, err
		}
		if err := matchKey(cert, key); err != nil {
			return nil, err
		}
		before := spec.RenewBeforeDays
		if before == 0 {
			before = 30
		}
		if before < 0 {
			return nil, errors.New("renewBeforeDays must be nonnegative")
		}
		if operation == "ensure" && !force && old.Generation == state.Active && reflect.DeepEqual(old.Spec, spec) && s.now().After(cert.NotBefore) && s.now().AddDate(0, 0, before).Before(cert.NotAfter) && matchesPolicy(cert, spec, s.now()) {
			if err := s.PublishRecord(state, *old); err != nil {
				return nil, err
			}
			if adopted || len(state.Pending) > 0 {
				if err := s.Save(state); err != nil {
					return nil, err
				}
			}
			return old, nil
		}
		if operation != "rotate" && spec.Algorithm != "" && old.Spec.Algorithm != "" && spec.Algorithm != old.Spec.Algorithm {
			return nil, errors.New("algorithm change requires explicit rotation")
		}
	}
	if operation == "renew" && old == nil {
		return nil, errors.New("cannot renew absent certificate")
	}
	if key != nil && operation != "rotate" && !keyAlgorithmMatches(key, spec.Algorithm) {
		return nil, errors.New("existing key algorithm differs from policy; explicit rotation required")
	}
	if key == nil || operation == "rotate" {
		key, err = newKey(spec.Algorithm)
		if err != nil {
			return nil, err
		}
	}
	template, err := leafTemplate(spec, s.now())
	if err != nil {
		return nil, err
	}
	parent, err := ParseCert(g.Certificate)
	if err != nil {
		return nil, err
	}
	signer, err := s.signer(g)
	if err != nil {
		return nil, err
	}
	value, err := sign(template, parent, key.Public(), signer, s.now())
	if err != nil {
		return nil, err
	}
	cert, err := ParseCert(value)
	if err != nil {
		return nil, err
	}
	chain, err := s.Chain(state.ID, g.ID)
	if err != nil {
		return nil, err
	}
	if err := verifyChain(cert, chain, s.now()); err != nil {
		return nil, err
	}
	private, err := keyPEM(key)
	if err != nil {
		return nil, err
	}
	if old != nil && operation != "rotate" {
		private = old.Key
	}
	record := Record{ID: id, Generation: g.ID, Serial: cert.SerialNumber.Text(16), Certificate: value, Key: private, Spec: spec}
	state.Records = append(state.Records, record)
	if err := s.PublishRecord(state, record); err != nil {
		return nil, err
	}
	if err := s.Save(state); err != nil {
		return nil, err
	}
	return &record, nil
}
func (s Store) ImportCertificate(id string, spec manifest.Certificate, certificate, private string) (*Record, error) {
	if err := validID(id); err != nil {
		return nil, err
	}
	state, err := s.Open(spec.Issuer)
	if err != nil {
		return nil, err
	}
	if current(state, id) != nil {
		return nil, errors.New("certificate already managed")
	}
	cert, err := ParseCert(certificate)
	if err != nil {
		return nil, err
	}
	if cert.IsCA {
		return nil, errors.New("use ca import for CA certificates")
	}
	if private != "" {
		key, err := ParseKey(private)
		if err != nil {
			return nil, err
		}
		if err := matchKey(cert, key); err != nil {
			return nil, err
		}
	}
	gen := 0
	for _, g := range state.Generations {
		issuer, e := ParseCert(g.Certificate)
		if e != nil {
			return nil, e
		}
		if cert.CheckSignatureFrom(issuer) == nil {
			gen = g.ID
			break
		}
	}
	if gen == 0 {
		return nil, errors.New("certificate issuer is unknown")
	}
	r := Record{ID: id, Generation: gen, Serial: cert.SerialNumber.Text(16), Certificate: certPEM(cert.Raw), Key: private, Spec: spec, External: private == ""}
	state.Records = append(state.Records, r)
	if private != "" {
		if err := s.PublishRecord(state, r); err != nil {
			return nil, err
		}
	}
	return &r, s.Save(state)
}
func (s Store) Verify(issuer, id string, checkKey bool) error {
	state, err := s.Public(issuer)
	if err != nil {
		return err
	}
	if state.Incomplete {
		return errors.New("PKI operation is incomplete")
	}
	r := current(state, id)
	if r == nil {
		return errors.New("certificate not found")
	}
	if r.RevokedAt != nil {
		return errors.New("certificate revoked")
	}
	for _, rev := range state.Revocations {
		if rev.Generation == r.Generation && rev.Serial == r.Serial {
			return errors.New("certificate serial revoked")
		}
	}
	g, err := generation(state, r.Generation)
	if err != nil {
		return err
	}
	if g.Retired {
		return errors.New("issuer generation retired")
	}
	if err := s.checkIssuer(state.ID, g.ID, map[string]bool{}); err != nil {
		return err
	}
	cert, err := ParseCert(r.Certificate)
	if err != nil {
		return err
	}
	chain, err := s.Chain(issuer, r.Generation)
	if err != nil {
		return err
	}
	if err := verifyChain(cert, chain, s.now()); err != nil {
		return err
	}
	if checkKey {
		private, err := s.Load(issuer)
		if err != nil {
			return err
		}
		r = current(private, id)
		key, err := ParseKey(r.Key)
		if err != nil {
			return err
		}
		return matchKey(cert, key)
	}
	return nil
}
func (s Store) Revoke(issuer, id, serialText string, reason int) (*State, error) {
	if reason < 0 || reason > 10 || reason == 7 || reason == 8 {
		return nil, errors.New("unsupported revocation reason")
	}
	state, err := s.Open(issuer)
	if err != nil {
		return nil, err
	}
	gen := state.Active
	var record *Record
	if serialText != "" {
		for i := range state.Records {
			if state.Records[i].Serial == strings.TrimPrefix(serialText, "0x") {
				record = &state.Records[i]
				break
			}
		}
	} else {
		record = current(state, id)
	}
	if record != nil {
		serialText = record.Serial
		gen = record.Generation
		if record.RevokedAt == nil {
			now := s.now()
			record.RevokedAt = &now
			record.Reason = reason
		}
	} else if serialText == "" {
		return nil, errors.New("certificate not found")
	}
	serialValue, ok := new(big.Int).SetString(strings.TrimPrefix(serialText, "0x"), 16)
	if !ok || serialValue.Sign() <= 0 || len(serialValue.Bytes()) > 20 {
		return nil, errors.New("invalid hexadecimal certificate serial")
	}
	found := false
	for _, rev := range state.Revocations {
		if rev.Generation == gen && rev.Serial == serialValue.Text(16) {
			found = true
		}
	}
	if !found {
		state.Revocations = append(state.Revocations, Revocation{Generation: gen, Serial: serialValue.Text(16), Time: s.now(), Reason: reason})
	}
	state.PendingCRLs[gen] = true
	if err := s.Save(state); err != nil {
		return nil, err
	}
	_, err = s.CRL(issuer, gen, 7)
	if err != nil {
		return state, errors.Wrap(err, "revocation recorded; CRL remains pending, retry 'deploy pki crl generate'")
	}
	return state, nil
}
func (s Store) CRL(issuer string, gen, days int) (string, error) {
	if days < 1 {
		return "", errors.New("CRL validity must be positive")
	}
	state, err := s.Open(issuer)
	if err != nil {
		return "", err
	}
	if gen == 0 {
		gen = state.Active
	}
	g, err := generation(state, gen)
	if err != nil {
		return "", err
	}
	cert, err := ParseCert(g.Certificate)
	if err != nil {
		return "", err
	}
	key, err := s.signer(g)
	if err != nil {
		return "", err
	}
	if err := issuerKeyID(cert); err != nil {
		return "", err
	}
	if cert.KeyUsage&x509.KeyUsageCRLSign == 0 {
		return "", errors.New("issuer lacks CRL signing usage")
	}
	if !s.now().Before(cert.NotAfter) {
		return "", errors.New("CRL issuer expired")
	}
	var entries []x509.RevocationListEntry
	for _, rev := range state.Revocations {
		if rev.Generation == gen {
			serialValue, ok := new(big.Int).SetString(rev.Serial, 16)
			if !ok {
				return "", errors.New("invalid stored revocation serial")
			}
			entries = append(entries, x509.RevocationListEntry{SerialNumber: serialValue, RevocationTime: rev.Time, ReasonCode: rev.Reason})
		}
	}
	state.CRLNumbers[gen]++
	next := s.now().AddDate(0, 0, days)
	if next.After(cert.NotAfter) {
		next = cert.NotAfter
	}
	template := &x509.RevocationList{Number: newBig(state.CRLNumbers[gen]), ThisUpdate: s.now(), NextUpdate: next, RevokedCertificateEntries: entries}
	der, err := x509.CreateRevocationList(rand.Reader, template, cert, key)
	if err != nil {
		return "", err
	}
	value := string(pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der}))
	state.CRLs[gen] = value
	delete(state.PendingCRLs, gen)
	return value, s.Save(state)
}
func (s Store) VerifyCRL(issuer string, gen int) error {
	state, err := s.Public(issuer)
	if err != nil {
		return err
	}
	if state.Incomplete {
		return errors.New("PKI state incomplete")
	}
	if gen == 0 {
		gen = state.Active
	}
	g, err := generation(state, gen)
	if err != nil {
		return err
	}
	cert, err := ParseCert(g.Certificate)
	if err != nil {
		return err
	}
	block, _ := pem.Decode([]byte(state.CRLs[gen]))
	if block == nil {
		return errors.New("CRL not generated")
	}
	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		return err
	}
	if err := crl.CheckSignatureFrom(cert); err != nil {
		return err
	}
	if s.now().Before(crl.ThisUpdate) || !s.now().Before(crl.NextUpdate) {
		return errors.New("CRL outside validity period")
	}
	return nil
}

// CSR creation stores its key only in encrypted admin state; CSR signing never
// copies requested extensions without the issuer's explicit policy.
func (s Store) CreateCSR(id string, spec manifest.Certificate) (string, error) {
	if err := validID(id); err != nil {
		return "", err
	}
	path := s.requestPath(id)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		return "", errors.New("CSR request already exists or cannot be inspected")
	}
	key, err := newKey(spec.Algorithm)
	if err != nil {
		return "", err
	}
	template, err := leafTemplate(spec, s.now())
	if err != nil {
		return "", err
	}
	csr := &x509.CertificateRequest{Subject: template.Subject, DNSNames: template.DNSNames, IPAddresses: template.IPAddresses, EmailAddresses: template.EmailAddresses, URIs: template.URIs}
	der, err := x509.CreateCertificateRequest(rand.Reader, csr, key)
	if err != nil {
		return "", err
	}
	private, err := keyPEM(key)
	if err != nil {
		return "", err
	}
	value := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
	data, _ := json.Marshal(map[string]string{"key": private, "csr": value})
	if err := os.MkdirAll(dir(path), 0700); err != nil {
		return "", err
	}
	return value, sops.Create(s.Conf, path, data)
}
func (s Store) SignCSR(id string, spec manifest.Certificate, value string) (*Record, error) {
	block, _ := pem.Decode([]byte(value))
	if block == nil {
		return nil, errors.New("invalid CSR PEM")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, err
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, err
	}
	template, err := leafTemplate(spec, s.now())
	if err != nil {
		return nil, err
	}
	if !slices.Equal(csr.DNSNames, template.DNSNames) || !slices.EqualFunc(csr.IPAddresses, template.IPAddresses, func(a, b net.IP) bool { return a.Equal(b) }) || !slices.Equal(csr.EmailAddresses, template.EmailAddresses) || len(csr.URIs) != len(template.URIs) {
		return nil, errors.New("CSR SANs differ from explicit issuance policy")
	}
	for i := range csr.URIs {
		if csr.URIs[i].String() != template.URIs[i].String() {
			return nil, errors.New("CSR URI differs from policy")
		}
	}
	state, err := s.Open(spec.Issuer)
	if err != nil {
		return nil, err
	}
	g, err := generation(state, state.Active)
	if err != nil {
		return nil, err
	}
	parent, err := ParseCert(g.Certificate)
	if err != nil {
		return nil, err
	}
	key, err := s.signer(g)
	if err != nil {
		return nil, err
	}
	cert, err := sign(template, parent, csr.PublicKey, key, s.now())
	if err != nil {
		return nil, err
	}
	parsed, err := ParseCert(cert)
	if err != nil {
		return nil, err
	}
	chain, err := s.Chain(state.ID, g.ID)
	if err != nil {
		return nil, err
	}
	if err := verifyChain(parsed, chain, s.now()); err != nil {
		return nil, err
	}
	r := Record{ID: id, Generation: g.ID, Serial: parsed.SerialNumber.Text(16), Certificate: cert, Spec: spec, External: true}
	if private, e := s.RequestKey(id); e == nil {
		requestKey, e := ParseKey(private)
		if e != nil {
			return nil, e
		}
		if e := matchKey(parsed, requestKey); e != nil {
			return nil, e
		}
		r.Key = private
		r.External = false
		if e := s.PublishRecord(state, r); e != nil {
			return nil, e
		}
	}
	state.Records = append(state.Records, r)
	return &r, s.Save(state)
}

// Keep raw key outputs out of generic JSON output; callers select exports explicitly.
func PublicRecord(r *Record) *Record { copy := *r; copy.Key = ""; return &copy }
