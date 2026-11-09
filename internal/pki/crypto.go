// Package pki implements local CA and certificate lifecycle using standard X.509
// primitives. Private state is stored through deploy's existing SOPS boundary.
package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"git.tatikoma.dev/corpix/atlas/errors"
	"git.tatikoma.dev/corpix/deploy/internal/manifest"
)

func newKey(algorithm string) (crypto.Signer, error) {
	switch strings.ToLower(algorithm) {
	case "", "p256":
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "p384":
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "ed25519":
		_, key, err := ed25519.GenerateKey(rand.Reader)
		return key, err
	case "rsa2048":
		return rsa.GenerateKey(rand.Reader, 2048)
	case "rsa3072":
		return rsa.GenerateKey(rand.Reader, 3072)
	case "rsa4096":
		return rsa.GenerateKey(rand.Reader, 4096)
	}
	return nil, errors.Errorf("unsupported key algorithm %q", algorithm)
}

func keyPEM(key crypto.Signer) (string, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), nil
}

func ParseKey(value string) (crypto.Signer, error) {
	block, rest := pem.Decode([]byte(value))
	if block == nil || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, errors.New("invalid private-key PEM")
	}
	var key any
	var err error
	switch block.Type {
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	default:
		return nil, errors.New("unsupported private key PEM type")
	}
	if err != nil {
		return nil, err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, errors.New("private key cannot sign")
	}
	return signer, nil
}

func ParseCert(value string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(value))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("invalid certificate PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}

func certPEM(der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

func matchKey(cert *x509.Certificate, key crypto.Signer) error {
	a, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return err
	}
	b, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return err
	}
	if string(a) != string(b) {
		return errors.New("certificate and private key do not match")
	}
	return nil
}

func serial() (*big.Int, error) {
	for {
		v, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		if err != nil || v.Sign() > 0 {
			return v, err
		}
	}
}

func oid(value string) (asn1.ObjectIdentifier, error) {
	parts := strings.Split(value, ".")
	out := make(asn1.ObjectIdentifier, len(parts))
	if len(parts) < 2 {
		return nil, errors.New("invalid extension OID")
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return nil, errors.New("invalid extension OID")
		}
		out[i] = n
	}
	if out[0] > 2 || (out[0] < 2 && out[1] > 39) {
		return nil, errors.New("invalid extension OID")
	}
	return out, nil
}

func leafTemplate(spec manifest.Certificate, now time.Time) (*x509.Certificate, error) {
	if spec.ValidityDays == 0 {
		spec.ValidityDays = 90
	}
	if spec.ValidityDays < 1 {
		return nil, errors.New("validityDays must be positive")
	}
	sn, err := serial()
	if err != nil {
		return nil, err
	}
	c := &x509.Certificate{
		SerialNumber:          sn,
		Subject:               pkix.Name{CommonName: spec.Subject},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.AddDate(0, 0, spec.ValidityDays),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
	}
	if len(spec.KeyUsage) > 0 {
		c.KeyUsage = 0
		for _, usage := range spec.KeyUsage {
			switch usage {
			case "digitalSignature":
				c.KeyUsage |= x509.KeyUsageDigitalSignature
			case "keyEncipherment":
				c.KeyUsage |= x509.KeyUsageKeyEncipherment
			case "keyAgreement":
				c.KeyUsage |= x509.KeyUsageKeyAgreement
			case "dataEncipherment":
				c.KeyUsage |= x509.KeyUsageDataEncipherment
			default:
				return nil, errors.Errorf("unsupported leaf key usage %q", usage)
			}
		}
	}
	if spec.Organization != "" {
		c.Subject.Organization = []string{spec.Organization}
	}
	if spec.UID != "" {
		c.Subject.ExtraNames = append(c.Subject.ExtraNames, pkix.AttributeTypeAndValue{Type: asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 1}, Value: spec.UID})
	}
	c.DNSNames = spec.DNS
	c.EmailAddresses = spec.Email
	for _, s := range spec.IP {
		ip := net.ParseIP(s)
		if ip == nil {
			return nil, errors.Errorf("invalid IP SAN %q", s)
		}
		c.IPAddresses = append(c.IPAddresses, ip)
	}
	for _, s := range spec.URI {
		u, err := url.Parse(s)
		if err != nil || u.Scheme == "" {
			return nil, errors.Errorf("invalid URI SAN %q", s)
		}
		c.URIs = append(c.URIs, u)
	}
	usages := spec.Usage
	if len(usages) == 0 {
		usages = []string{"serverAuth"}
	}
	for _, usage := range usages {
		switch usage {
		case "serverAuth":
			if len(c.DNSNames)+len(c.IPAddresses) == 0 {
				return nil, errors.New("serverAuth requires DNS or IP SANs")
			}
			c.ExtKeyUsage = append(c.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
		case "clientAuth":
			c.ExtKeyUsage = append(c.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
		case "codeSigning":
			c.ExtKeyUsage = append(c.ExtKeyUsage, x509.ExtKeyUsageCodeSigning)
		case "emailProtection":
			c.ExtKeyUsage = append(c.ExtKeyUsage, x509.ExtKeyUsageEmailProtection)
		default:
			return nil, errors.Errorf("unsupported certificate usage %q", usage)
		}
	}
	seen := map[string]bool{}
	for _, ext := range spec.Extensions {
		if seen[ext.OID] || strings.HasPrefix(ext.OID, "2.5.29.") {
			return nil, errors.New("duplicate or reserved extension OID")
		}
		seen[ext.OID] = true
		id, err := oid(ext.OID)
		if err != nil {
			return nil, err
		}
		var der []byte
		if ext.UTF8 != nil {
			if ext.DER != "" {
				return nil, errors.New("extension must specify one value")
			}
			der, err = asn1.MarshalWithParams(*ext.UTF8, "utf8")
		} else {
			der, err = base64.StdEncoding.DecodeString(ext.DER)
		}
		if err != nil || len(der) == 0 {
			return nil, errors.New("invalid extension DER")
		}
		var raw asn1.RawValue
		if rest, e := asn1.Unmarshal(der, &raw); e != nil || len(rest) != 0 {
			return nil, errors.New("extension value must be one DER value")
		}
		c.ExtraExtensions = append(c.ExtraExtensions, pkix.Extension{Id: id, Critical: ext.Critical, Value: der})
	}
	return c, nil
}

func authorityTemplate(spec manifest.Authority, now time.Time) (*x509.Certificate, error) {
	days := spec.ValidityDays
	if days == 0 {
		days = 3650
		if spec.Issuer != "" {
			days = 1825
		}
	}
	if days < 1 {
		return nil, errors.New("validityDays must be positive")
	}
	sn, err := serial()
	if err != nil {
		return nil, err
	}
	c := &x509.Certificate{
		SerialNumber:                sn,
		Subject:                     pkix.Name{CommonName: spec.Subject},
		NotBefore:                   now.Add(-5 * time.Minute),
		NotAfter:                    now.AddDate(0, 0, days),
		BasicConstraintsValid:       true,
		IsCA:                        true,
		KeyUsage:                    x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		MaxPathLen:                  -1,
		PermittedDNSDomains:         spec.DNSConstraints,
		PermittedDNSDomainsCritical: len(spec.DNSConstraints) > 0,
	}
	if spec.PathLen != nil {
		if *spec.PathLen < 0 {
			return nil, errors.New("pathLen must be nonnegative")
		}
		c.MaxPathLen = *spec.PathLen
		c.MaxPathLenZero = *spec.PathLen == 0
	}
	return c, nil
}

func sign(template, parent *x509.Certificate, public crypto.PublicKey, key crypto.Signer, now time.Time) (string, error) {
	if parent != template {
		if !parent.IsCA || parent.KeyUsage&x509.KeyUsageCertSign == 0 {
			return "", errors.New("issuer is not authorized to sign certificates")
		}
		if now.Before(parent.NotBefore) || !now.Before(parent.NotAfter) {
			return "", errors.New("issuer is outside its validity period")
		}
		if template.NotAfter.After(parent.NotAfter) {
			template.NotAfter = parent.NotAfter
		}
		if template.NotBefore.Before(parent.NotBefore) {
			template.NotBefore = parent.NotBefore
		}
		if template.IsCA && parent.MaxPathLenZero {
			return "", errors.New("issuer forbids intermediate authorities")
		}
		if template.IsCA && parent.MaxPathLen > 0 && (template.MaxPathLen < 0 || template.MaxPathLen >= parent.MaxPathLen) {
			return "", errors.New("intermediate exceeds issuer path-length constraint")
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, public, key)
	if err != nil {
		return "", err
	}
	return certPEM(der), nil
}

func matchesPolicy(cert *x509.Certificate, spec manifest.Certificate, now time.Time) bool {
	template, err := leafTemplate(spec, now)
	if err != nil {
		return false
	}
	if cert.KeyUsage != template.KeyUsage || cert.Subject.CommonName != template.Subject.CommonName || !slices.Equal(cert.Subject.Organization, template.Subject.Organization) || !slices.Equal(cert.DNSNames, template.DNSNames) || !slices.EqualFunc(cert.IPAddresses, template.IPAddresses, func(a, b net.IP) bool {
		return a.Equal(b)
	}) || !slices.Equal(cert.EmailAddresses, template.EmailAddresses) || !slices.Equal(cert.ExtKeyUsage, template.ExtKeyUsage) {
		return false
	}
	if len(cert.URIs) != len(template.URIs) {
		return false
	}
	for i := range cert.URIs {
		if cert.URIs[i].String() != template.URIs[i].String() {
			return false
		}
	}
	for _, expected := range template.ExtraExtensions {
		found := false
		for _, actual := range cert.Extensions {
			if expected.Id.Equal(actual.Id) && expected.Critical == actual.Critical && string(expected.Value) == string(actual.Value) {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	if spec.UID != "" {
		found := false
		for _, name := range cert.Subject.Names {
			if name.Type.Equal(asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 1}) && name.Value == spec.UID {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// RFC 5280 method 1 key identifier, needed for imported legacy CA certificates
// without an SKI extension when signing a CRL. This does not change their DER.
func issuerKeyID(cert *x509.Certificate) error {
	if len(cert.SubjectKeyId) > 0 {
		return nil
	}
	var info struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(cert.RawSubjectPublicKeyInfo, &info); err != nil {
		return err
	}
	sum := sha1.Sum(info.PublicKey.Bytes)
	cert.SubjectKeyId = sum[:]
	return nil
}

func keyAlgorithmMatches(key crypto.Signer, algorithm string) bool {
	if algorithm == "" {
		return true
	}
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		return (algorithm == "p256" && k.Curve == elliptic.P256()) || (algorithm == "p384" && k.Curve == elliptic.P384())
	case *rsa.PrivateKey:
		return algorithm == "rsa"+strconv.Itoa(k.N.BitLen())
	case ed25519.PrivateKey:
		return algorithm == "ed25519"
	}
	return false
}
