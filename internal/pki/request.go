package pki

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"git.tatikoma.dev/corpix/atlas/errors"
	"git.tatikoma.dev/corpix/deploy/internal/manifest"
	"git.tatikoma.dev/corpix/deploy/internal/sops"
	"os"
)

func (s Store) RequestKey(id string) (string, error) {
	if err := validID(id); err != nil {
		return "", err
	}
	f, err := sops.Open(s.requestPath(id))
	if err != nil {
		return "", err
	}
	return f.Get("key")
}
func (s Store) CreateAuthorityCSR(id string, policy manifest.Authority) (string, error) {
	if err := validID(id); err != nil {
		return "", err
	}
	key, err := newKey(policy.Algorithm)
	if err != nil {
		return "", err
	}
	template, err := authorityTemplate(policy, s.now())
	if err != nil {
		return "", err
	}
	if template.Subject.CommonName == "" {
		template.Subject.CommonName = id
	}
	request := &x509.CertificateRequest{Subject: template.Subject}
	der, err := x509.CreateCertificateRequest(rand.Reader, request, key)
	if err != nil {
		return "", err
	}
	value := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
	private, err := keyPEM(key)
	if err != nil {
		return "", err
	}
	path := s.requestPath(id)
	if err := os.MkdirAll(dir(path), 0700); err != nil {
		return "", err
	}
	data, _ := json.Marshal(map[string]string{"key": private, "csr": value})
	return value, sops.Create(s.Conf, path, data)
}
func (s Store) SignAuthorityCSR(id string, policy manifest.Authority, value string) (string, error) {
	if err := validID(id); err != nil {
		return "", err
	}
	if policy.Issuer == "" {
		return "", errors.New("CA CSR signing requires an explicit parent issuer")
	}
	block, _ := pem.Decode([]byte(value))
	if block == nil {
		return "", errors.New("invalid CA CSR")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return "", err
	}
	if err := csr.CheckSignature(); err != nil {
		return "", err
	}
	if policy.Subject != "" && csr.Subject.CommonName != policy.Subject {
		return "", errors.New("CA CSR subject differs from policy")
	}
	template, err := authorityTemplate(policy, s.now())
	if err != nil {
		return "", err
	}
	if template.Subject.CommonName == "" {
		template.Subject.CommonName = csr.Subject.CommonName
	}
	state, err := s.Open(policy.Issuer)
	if err != nil {
		return "", err
	}
	g, err := generation(state, state.Active)
	if err != nil {
		return "", err
	}
	if err := s.checkIssuer(state.ID, g.ID, map[string]bool{}); err != nil {
		return "", err
	}
	parent, err := ParseCert(g.Certificate)
	if err != nil {
		return "", err
	}
	key, err := s.signer(g)
	if err != nil {
		return "", err
	}
	certificate, err := sign(template, parent, csr.PublicKey, key, s.now())
	if err != nil {
		return "", err
	}
	cert, err := ParseCert(certificate)
	if err != nil {
		return "", err
	}
	state.Records = append(state.Records, Record{ID: "ca-" + id + "-" + cert.SerialNumber.Text(16), Serial: cert.SerialNumber.Text(16), Generation: g.ID, Certificate: certificate, External: true})
	return certificate, s.Save(state)
}
func (s Store) checkIssuer(id string, gen int, seen map[string]bool) error {
	if seen[id] {
		return errors.New("cyclic authority dependency")
	}
	seen[id] = true
	state, err := s.Public(id)
	if err != nil {
		return err
	}
	if state.Incomplete {
		return errors.New("issuer has incomplete state")
	}
	g, err := generation(state, gen)
	if err != nil {
		return err
	}
	if g.Retired {
		return errors.New("issuer generation retired")
	}
	cert, err := ParseCert(g.Certificate)
	if err != nil {
		return err
	}
	if s.now().Before(cert.NotBefore) || !s.now().Before(cert.NotAfter) {
		return errors.New("issuer expired or not yet valid")
	}
	if g.Issuer != "" {
		parent, err := s.Public(g.Issuer)
		if err != nil {
			return err
		}
		for _, rev := range parent.Revocations {
			if rev.Generation == g.IssuerGeneration && rev.Serial == cert.SerialNumber.Text(16) {
				return errors.New("intermediate authority revoked")
			}
		}
		return s.checkIssuer(g.Issuer, g.IssuerGeneration, seen)
	}
	return nil
}
