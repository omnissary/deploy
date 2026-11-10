package pki

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"git.tatikoma.dev/corpix/atlas/errors"
	"git.tatikoma.dev/corpix/deploy/internal/atomicfile"
	"git.tatikoma.dev/corpix/deploy/internal/manifest"
	"git.tatikoma.dev/corpix/deploy/internal/sops"
	"git.tatikoma.dev/corpix/deploy/internal/vars"
)

type Generation struct {
	NotAfter         time.Time `json:"notAfter"`
	Fingerprint      string    `json:"fingerprint"`
	Certificate      string    `json:"certificate"`
	Key              string    `json:"key,omitempty"`
	Issuer           string    `json:"issuer,omitempty"`
	Revisions        []string  `json:"revisions,omitempty"`
	ID               int       `json:"id"`
	IssuerGeneration int       `json:"issuerGeneration,omitempty"`
	Retired          bool      `json:"retired"`
}
type Record struct {
	NotAfter    time.Time            `json:"notAfter"`
	RevokedAt   *time.Time           `json:"revokedAt,omitempty"`
	Fingerprint string               `json:"fingerprint"`
	ID          string               `json:"id"`
	Serial      string               `json:"serial"`
	Certificate string               `json:"certificate"`
	Key         string               `json:"key,omitempty"`
	Spec        manifest.Certificate `json:"spec"`
	Generation  int                  `json:"generation"`
	Reason      int                  `json:"reason,omitempty"`
	External    bool                 `json:"external,omitempty"`
}
type Publication struct {
	Values map[string]string `json:"values"`
	Target manifest.Target   `json:"target"`
}
type Revocation struct {
	Time       time.Time `json:"time"`
	Serial     string    `json:"serial"`
	Generation int       `json:"generation"`
	Reason     int       `json:"reason"`
}

type State struct {
	PendingCRLs map[int]bool       `json:"pendingCRLs,omitempty"`
	CRLs        map[int]string     `json:"crls"`
	CRLNumbers  map[int]int64      `json:"crlNumbers"`
	ID          string             `json:"id"`
	StoreHash   string             `json:"storeHash,omitempty"`
	Revocations []Revocation       `json:"revocations,omitempty"`
	Generations []Generation       `json:"generations"`
	Records     []Record           `json:"records"`
	Pending     []Publication      `json:"pending,omitempty"`
	Policy      manifest.Authority `json:"policy"`
	Active      int                `json:"active"`
	Incomplete  bool               `json:"incomplete,omitempty"`
	Imported    bool               `json:"imported,omitempty"`
}
type Store struct {
	Now  func() time.Time
	Root string
	Conf string
}

func (s Store) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

func (s Store) privatePath(id string) string {
	return filepath.Join(vars.AdminDir(s.Root), "pki", id+".yaml")
}

func (s Store) publicPath(id string) string { return filepath.Join(s.Root, "vars", "pki", id+".json") }

func validID(id string) error {
	if !vars.ValidName(id) {
		return errors.New("invalid PKI resource name")
	}
	return nil
}

func (s Store) TargetPath(t manifest.Target) (string, error) {
	if err := validID(t.Name); err != nil {
		return "", err
	}
	if t.Group {
		return vars.SharedSecretsPath(s.Root, t.Name), nil
	}
	if t.Name == vars.SharedDirName {
		return "", errors.New("reserved machine name")
	}
	return vars.MachineSecretsPath(s.Root, t.Name), nil
}

func (s Store) Load(id string) (*State, error) {
	if err := validID(id); err != nil {
		return nil, err
	}
	file, err := sops.Open(s.privatePath(id))
	if err != nil {
		return nil, err
	}
	value, err := file.Get("state")
	if err != nil {
		return nil, err
	}
	var state State
	decoder := json.NewDecoder(strings.NewReader(value))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil {
		return nil, err
	}
	if state.ID != id {
		return nil, errors.New("PKI state ID mismatch")
	}
	if state.CRLs == nil {
		state.CRLs = map[int]string{}
	}
	if state.CRLNumbers == nil {
		state.CRLNumbers = map[int]int64{}
	}
	if state.PendingCRLs == nil {
		state.PendingCRLs = map[int]bool{}
	}
	return &state, nil
}
func (s Store) Exists(id string) bool { _, err := os.Stat(s.privatePath(id)); return err == nil }
func (s Store) writePrivate(state *State) error {
	path := s.privatePath(state.ID)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	state.StoreHash = ""
	state.Incomplete = false
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		initial, _ := json.Marshal(map[string]string{"state": string(data)})
		return sops.Create(s.Conf, path, initial)
	}
	return sops.Edit(path, func(f *sops.File) error { f.Set("state", string(data)); return nil })
}

func digestFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func (s Store) publish(state *State) error {
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	var view State
	if err := json.Unmarshal(data, &view); err != nil {
		return err
	}
	for i := range view.Generations {
		g := &view.Generations[i]
		cert, e := ParseCert(g.Certificate)
		if e != nil {
			return e
		}
		g.NotAfter = cert.NotAfter
		g.Fingerprint = fingerprint(cert)
		view.Generations[i].Key = ""
	}
	for i := range view.Records {
		r := &view.Records[i]
		cert, e := ParseCert(r.Certificate)
		if e != nil {
			return e
		}
		r.NotAfter = cert.NotAfter
		r.Fingerprint = fingerprint(cert)
		view.Records[i].Key = ""
	}
	view.Incomplete = len(view.Pending) > 0
	view.Pending = nil
	view.StoreHash, err = digestFile(s.privatePath(state.ID))
	if err != nil {
		return err
	}
	out, err := json.MarshalIndent(view, "", "  ")
	if err != nil {
		return err
	}
	path := s.publicPath(state.ID)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return atomicfile.Write(path, append(out, '\n'), 0o644)
}

// Save persists a recovery journal inside encrypted authoritative state before
// publishing any consumer bundles. Callers serialize mutations with repolock.
func (s Store) Save(state *State) error {
	if err := validID(state.ID); err != nil {
		return err
	}
	if err := validateSerials(state); err != nil {
		return err
	}
	if err := s.writePrivate(state); err != nil {
		return err
	}
	if err := s.publish(state); err != nil {
		return err
	}
	return s.Resume(state)
}

func (s Store) Resume(state *State) error {
	for _, p := range state.Pending {
		path, err := s.TargetPath(p.Target)
		if err != nil {
			return err
		}
		if err := sops.Edit(path, func(f *sops.File) error {
			for key, value := range p.Values {
				if key != "" {
					f.Set(key, value)
				}
			}
			return nil
		}); err != nil {
			return errors.Wrap(err, "PKI publication pending; next mutating PKI operation will retry")
		}
	}
	if len(state.Pending) > 0 {
		state.Pending = nil
		if err := s.writePrivate(state); err != nil {
			return err
		}
	}
	return s.publish(state)
}

func (s Store) Open(id string) (*State, error) {
	state, err := s.Load(id)
	if err != nil {
		return nil, err
	}
	if err := s.Resume(state); err != nil {
		return nil, err
	}
	return state, nil
}

func (s Store) Public(id string) (*State, error) {
	if err := validID(id); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(s.publicPath(id))
	if err != nil {
		return nil, err
	}
	var state State
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil {
		return nil, err
	}
	hash, err := digestFile(s.privatePath(id))
	if err != nil {
		return nil, err
	}
	state.Incomplete = state.Incomplete || hash != state.StoreHash
	return &state, nil
}

func (s Store) List() ([]State, error) {
	files, err := filepath.Glob(filepath.Join(s.Root, "vars", "pki", "*.json"))
	if err != nil {
		return nil, err
	}
	var states []State
	for _, file := range files {
		id := filepath.Base(file)
		id = id[:len(id)-5]
		state, err := s.Public(id)
		if err != nil {
			return nil, err
		}
		states = append(states, *state)
	}
	sort.Slice(states, func(i, j int) bool { return states[i].ID < states[j].ID })
	return states, nil
}

func generation(state *State, id int) (*Generation, error) {
	for i := range state.Generations {
		if state.Generations[i].ID == id {
			return &state.Generations[i], nil
		}
	}
	return nil, errors.Errorf("unknown generation %d", id)
}

func validateSerials(state *State) error {
	seen := map[string]string{}
	for _, record := range state.Records {
		cert, err := ParseCert(record.Certificate)
		if err != nil {
			return err
		}
		key := fmt.Sprintf("%d:%s", record.Generation, cert.SerialNumber.Text(16))
		fp := fingerprint(cert)
		if previous, ok := seen[key]; ok && previous != fp {
			return errors.New("issuer reused a certificate serial")
		}
		seen[key] = fp
	}
	return nil
}
