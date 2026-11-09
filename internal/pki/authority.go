package pki

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"slices"
	"strings"
	"time"

	"git.tatikoma.dev/corpix/atlas/errors"
	"git.tatikoma.dev/corpix/deploy/internal/manifest"
	"git.tatikoma.dev/corpix/deploy/internal/sops"
)

func (s Store) signer(g *Generation) (crypto.Signer, error) {
	value := g.Key
	if g.Source != nil {
		path, err := s.TargetPath(*g.Source)
		if err != nil {
			return nil, err
		}
		file, err := sops.Open(path)
		if err != nil {
			return nil, err
		}
		value, err = file.Get(g.Source.Key)
		if err != nil {
			return nil, err
		}
	}
	if value == "" {
		return nil, errors.New("authority is public-only; no local signer")
	}
	key, err := ParseKey(value)
	if err != nil {
		return nil, err
	}
	cert, err := ParseCert(g.Certificate)
	if err != nil {
		return nil, err
	}
	if err := matchKey(cert, key); err != nil {
		return nil, err
	}
	return key, nil
}

func (s Store) Chain(id string, gen int) (string, error) { return s.chain(id, gen, map[string]bool{}) }

func (s Store) chain(id string, gen int, visited map[string]bool) (string, error) {
	if visited[id] {
		return "", errors.New("cyclic issuer chain")
	}
	visited[id] = true
	state, err := s.Public(id)
	if err != nil {
		return "", err
	}
	g, err := generation(state, gen)
	if err != nil {
		return "", err
	}
	value := g.Certificate
	if g.Issuer != "" {
		parent, err := s.chain(g.Issuer, g.IssuerGeneration, visited)
		if err != nil {
			return "", err
		}
		value += parent
	}
	return value, nil
}

func (s Store) makeGeneration(id string, policy manifest.Authority, key crypto.Signer, rawSubject ...[]byte) (Generation, error) {
	template, err := authorityTemplate(policy, s.now())
	if err != nil {
		return Generation{}, err
	}
	if template.Subject.CommonName == "" {
		template.Subject.CommonName = id
	}
	if len(rawSubject) > 0 {
		template.RawSubject = rawSubject[0]
	}
	parent := template
	signer := key
	g := Generation{}
	if policy.Issuer != "" {
		parentState, err := s.Public(policy.Issuer)
		if err != nil {
			return Generation{}, err
		}
		if err := s.checkIssuer(policy.Issuer, parentState.Active, map[string]bool{}); err != nil {
			return Generation{}, err
		}
	}
	if policy.Issuer != "" {
		if policy.Issuer == id {
			return g, errors.New("authority cannot issue itself as an intermediate")
		}
		issuer, err := s.Open(policy.Issuer)
		if err != nil {
			return g, err
		}
		parentGen, err := generation(issuer, issuer.Active)
		if err != nil {
			return g, err
		}
		if parentGen.Retired {
			return g, errors.New("issuer generation is retired")
		}
		parent, err = ParseCert(parentGen.Certificate)
		if err != nil {
			return g, err
		}
		signer, err = s.signer(parentGen)
		if err != nil {
			return g, err
		}
		g.Issuer = policy.Issuer
		g.IssuerGeneration = parentGen.ID
	}
	cert, err := sign(template, parent, key.Public(), signer, s.now())
	if err != nil {
		return g, err
	}
	if policy.Issuer != "" {
		parentState, e := s.Open(policy.Issuer)
		if e != nil {
			return g, e
		}
		parsed, e := ParseCert(cert)
		if e != nil {
			return g, e
		}
		parentState.Records = append(parentState.Records, Record{
			ID:          "ca-" + id + "-" + parsed.SerialNumber.Text(16),
			Generation:  g.IssuerGeneration,
			Serial:      parsed.SerialNumber.Text(16),
			Certificate: cert,
			External:    true,
		})
		if e := s.Save(parentState); e != nil {
			return g, e
		}
	}
	g.Certificate = cert
	g.Key, err = keyPEM(key)
	return g, err
}

func (s Store) Create(id string, policy manifest.Authority) (*State, error) {
	if err := validID(id); err != nil {
		return nil, err
	}
	if s.Exists(id) {
		return nil, errors.New("authority already exists; use renew or rotate")
	}
	if policy.Source != nil {
		return nil, errors.New("authority declares existing signing material; use ca import")
	}

	key, err := newKey(policy.Algorithm)
	if err != nil {
		return nil, err
	}
	g, err := s.makeGeneration(id, policy, key)
	if err != nil {
		return nil, err
	}
	g.ID = 1
	state := &State{
		ID:          id,
		Policy:      policy,
		Active:      1,
		Generations: []Generation{g},
		CRLs:        map[int]string{},
		CRLNumbers:  map[int]int64{},
	}
	if err := s.publishAuthority(state); err != nil {
		return nil, err
	}
	return state, s.Save(state)
}

func (s Store) ImportAuthority(id string, policy manifest.Authority, certificate, private string) (*State, error) {
	if err := validID(id); err != nil {
		return nil, err
	}
	if s.Exists(id) {
		return nil, errors.New("authority already exists")
	}
	if policy.Source != nil {
		path, err := s.TargetPath(*policy.Source)
		if err != nil {
			return nil, err
		}
		file, err := sops.Open(path)
		if err != nil {
			return nil, err
		}
		certificate, err = file.Get(policy.Source.Cert)
		if err != nil {
			return nil, err
		}
		private, err = file.Get(policy.Source.Key)
		if err != nil {
			return nil, err
		}
	}
	if private == "" && policy.Source == nil {
		if value, err := s.RequestKey(id); err == nil {
			private = value
		}
	}
	cert, err := ParseCert(certificate)
	if err != nil {
		return nil, err
	}
	if !cert.IsCA || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, errors.New("import requires a CA with certificate-signing usage")
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
	g := Generation{ID: 1, Certificate: certificate, Key: private, Source: policy.Source}
	if g.Source != nil {
		g.Key = ""
	}
	if policy.Issuer != "" {
		parent, err := s.Open(policy.Issuer)
		if err != nil {
			return nil, err
		}
		pg, err := generation(parent, parent.Active)
		if err != nil {
			return nil, err
		}
		pc, err := ParseCert(pg.Certificate)
		if err != nil {
			return nil, err
		}
		if err := cert.CheckSignatureFrom(pc); err != nil {
			return nil, err
		}
		g.Issuer = policy.Issuer
		g.IssuerGeneration = pg.ID
	}
	state := &State{
		ID:          id,
		Policy:      policy,
		Active:      1,
		Generations: []Generation{g},
		Imported:    true,
		CRLs:        map[int]string{},
		CRLNumbers:  map[int]int64{},
	}
	if err := s.publishAuthority(state); err != nil {
		return nil, err
	}
	return state, s.Save(state)
}

func (s Store) RenewAuthority(id string, policies ...manifest.Authority) (*State, error) {
	state, err := s.Open(id)
	if err != nil {
		return nil, err
	}
	if len(policies) > 0 {
		state.Policy = policies[0]
	}
	g, err := generation(state, state.Active)
	if err != nil {
		return nil, err
	}
	existing, err := ParseCert(g.Certificate)
	if err != nil {
		return nil, err
	}
	desired, err := authorityTemplate(state.Policy, s.now())
	if err != nil {
		return nil, err
	}
	if desired.Subject.CommonName == "" {
		desired.Subject.CommonName = existing.Subject.CommonName
	}
	if existing.Subject.CommonName != desired.Subject.CommonName || existing.MaxPathLen != desired.MaxPathLen || existing.MaxPathLenZero != desired.MaxPathLenZero || !slices.Equal(existing.PermittedDNSDomains, desired.PermittedDNSDomains) {
		return nil, errors.New("authority subject or constraints changed; use staged rotation")
	}
	key, err := s.signer(g)
	if err != nil {
		return nil, err
	}
	if !keyAlgorithmMatches(key, state.Policy.Algorithm) {
		return nil, errors.New("authority algorithm changed; use staged rotation")
	}
	next, err := s.makeGeneration(id, state.Policy, key, existing.RawSubject)
	if err != nil {
		return nil, err
	}
	g.Revisions = append(g.Revisions, g.Certificate)
	g.Certificate = next.Certificate
	g.Issuer = next.Issuer
	g.IssuerGeneration = next.IssuerGeneration
	if err := s.publishAuthority(state); err != nil {
		return nil, err
	}
	return state, s.Save(state)
}

func (s Store) RotateAuthority(id string, policies ...manifest.Authority) (*State, error) {
	state, err := s.Open(id)
	if err != nil {
		return nil, err
	}
	if len(policies) > 0 {
		state.Policy = policies[0]
	}
	key, err := newKey(state.Policy.Algorithm)
	if err != nil {
		return nil, err
	}
	g, err := s.makeGeneration(id, state.Policy, key)
	if err != nil {
		return nil, err
	}
	g.ID = len(state.Generations) + 1
	state.Generations = append(state.Generations, g)
	return state, s.Save(state)
}

func (s Store) Activate(id string, gen int) (*State, error) {
	state, err := s.Open(id)
	if err != nil {
		return nil, err
	}
	g, err := generation(state, gen)
	if err != nil {
		return nil, err
	}
	if g.Retired {
		return nil, errors.New("cannot activate retired generation")
	}
	cert, err := ParseCert(g.Certificate)
	if err != nil {
		return nil, err
	}
	if s.now().Before(cert.NotBefore) || !s.now().Before(cert.NotAfter) {
		return nil, errors.New("generation outside validity period")
	}
	if _, err := s.signer(g); err != nil {
		return nil, err
	}
	state.Active = gen
	if err := s.publishAuthority(state); err != nil {
		return nil, err
	}
	return state, s.Save(state)
}

func (s Store) Retire(id string, gen int, ackUntracked bool) (*State, error) {
	state, err := s.Open(id)
	if err != nil {
		return nil, err
	}
	if state.Active == gen {
		return nil, errors.New("cannot retire active signing generation")
	}
	if state.Imported && !ackUntracked {
		return nil, errors.New("imported authority may have untracked dependents; use --acknowledge-untracked after checking trust rollout")
	}
	for _, r := range state.Records {
		c, err := ParseCert(r.Certificate)
		if err != nil {
			return nil, err
		}
		if r.Generation == gen && r.RevokedAt == nil && s.now().Before(c.NotAfter) {
			return nil, errors.New("generation still has unexpired certificates")
		}
	}
	others, err := s.List()
	if err != nil {
		return nil, err
	}
	for _, other := range others {
		for _, g := range other.Generations {
			if g.Issuer == id && g.IssuerGeneration == gen && !g.Retired {
				c, err := ParseCert(g.Certificate)
				if err != nil {
					return nil, err
				}
				if s.now().Before(c.NotAfter) {
					return nil, errors.New("generation still has unretired intermediate authorities")
				}
			}
		}
	}
	g, err := generation(state, gen)
	if err != nil {
		return nil, err
	}
	g.Retired = true
	return state, s.Save(state)
}

func (s Store) Trust(ids []string) (string, error) {
	var result strings.Builder
	seen := map[string]bool{}
	for _, id := range ids {
		state, err := s.Public(id)
		if err != nil {
			return "", err
		}
		if state.Incomplete {
			return "", errors.New("authority has incomplete publications; run a mutating PKI operation to recover")
		}
		for _, g := range state.Generations {
			if g.Retired {
				continue
			}
			if err := s.checkIssuer(id, g.ID, map[string]bool{}); err != nil {
				return "", err
			}
			c, err := ParseCert(g.Certificate)
			if err != nil {
				return "", err
			}
			fp := fingerprint(c)
			if !seen[fp] {
				result.WriteString(g.Certificate)
				seen[fp] = true
			}
		}
	}
	return result.String(), nil
}

func verifyChain(cert *x509.Certificate, chain string, now time.Time) error {
	var certs []*x509.Certificate
	rest := []byte(chain)
	for len(rest) > 0 {
		block, next := pem.Decode(rest)
		if block == nil {
			if strings.TrimSpace(string(rest)) == "" {
				break
			}
			return errors.New("malformed issuer chain")
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return err
		}
		certs = append(certs, c)
		rest = next
	}
	if len(certs) == 0 {
		return errors.New("empty issuer chain")
	}
	roots := x509.NewCertPool()
	roots.AddCert(certs[len(certs)-1])
	intermediates := x509.NewCertPool()
	for _, c := range certs[:len(certs)-1] {
		intermediates.AddCert(c)
	}
	_, err := cert.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	return err
}

func (s Store) publishAuthority(state *State) error {
	if state.Policy.Target == nil {
		return nil
	}
	t := *state.Policy.Target
	// Preserve any signer whose old source is about to be replaced by publication.
	for i := range state.Generations {
		g := &state.Generations[i]
		if g.Source != nil && g.Source.Name == t.Name && g.Source.Group == t.Group && g.Source.Key == t.Key {
			key, err := s.signer(g)
			if err != nil {
				return err
			}
			private, err := keyPEM(key)
			if err != nil {
				return err
			}
			g.Key = private
			g.Source = nil
		}
	}
	g, err := generation(state, state.Active)
	if err != nil {
		return err
	}
	key, err := s.signer(g)
	if err != nil {
		return err
	}
	private, err := keyPEM(key)
	if err != nil {
		return err
	}
	chain := g.Certificate
	if g.Issuer != "" {
		parent, err := s.Chain(g.Issuer, g.IssuerGeneration)
		if err != nil {
			return err
		}
		chain += parent
	}
	values := map[string]string{}
	if t.Cert != "" {
		values[t.Cert] = g.Certificate
	}
	if t.Key != "" {
		values[t.Key] = private
	}
	if t.Chain != "" {
		values[t.Chain] = chain
	}
	if t.CA != "" {
		values[t.CA] = chain
	}
	state.Pending = append(state.Pending, Publication{Target: t, Values: values})
	return nil
}
