package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/urfave/cli/v2"

	"git.tatikoma.dev/corpix/atlas/errors"
	"git.tatikoma.dev/corpix/deploy/internal/atomicfile"
	"git.tatikoma.dev/corpix/deploy/internal/manifest"
	"git.tatikoma.dev/corpix/deploy/internal/pki"
)

func pkiStore(cfg *Config) pki.Store { return pki.Store{Root: cfg.FlakeDir, Conf: cfg.SopsConf} }
func readOptional(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	if path == "-" {
		data, err := io.ReadAll(os.Stdin)
		return string(data), err
	}
	data, err := os.ReadFile(path)
	return string(data), err
}

func readSpec(path string, out any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	return decoder.Decode(out)
}

func baseAuthorityPolicy(ctx *cli.Context, id string) (manifest.Authority, error) {
	var spec manifest.Authority
	if ctx.String("spec") != "" {
		err := readSpec(ctx.String("spec"), &spec)
		return spec, err
	}
	cfg := getConfig(ctx)
	store := pkiStore(cfg)
	if store.Exists(id) {
		state, err := store.Public(id)
		if err != nil {
			return spec, err
		}
		if state.Policy.PolicySource == "nix" {
			m, err := loadPolicyManifest(cfg)
			if err != nil {
				return spec, err
			}
			v, ok := m.Authorities[id]
			if !ok {
				return spec, errors.New("authority policy no longer declared; supply --spec")
			}
			return v, nil
		}
		return state.Policy, nil
	}
	m, err := loadPolicyManifest(cfg)
	if err != nil {
		return spec, err
	}
	v, ok := m.Authorities[id]
	if !ok {
		return spec, errors.New("authority policy not declared; supply --spec <public.json>")
	}
	return v, nil
}

func authorityPolicy(ctx *cli.Context, id string) (manifest.Authority, error) {
	spec, err := baseAuthorityPolicy(ctx, id)
	if err != nil {
		return spec, err
	}
	if ctx.String("issuer") != "" {
		spec.Issuer = ctx.String("issuer")
	}
	if spec.Target != nil {
		if err := spec.Target.Validate(); err != nil {
			return spec, err
		}
	}
	return spec, nil
}

func certificatePolicy(ctx *cli.Context, id string) (manifest.Certificate, error) {
	var spec manifest.Certificate
	if path := ctx.String("spec"); path != "" {
		if err := readSpec(path, &spec); err != nil {
			return spec, err
		}
	} else {
		states, err := pkiStore(getConfig(ctx)).List()
		if err != nil {
			return spec, err
		}
		found := false
		for _, state := range states {
			if ctx.String("issuer") != "" && ctx.String("issuer") != state.ID {
				continue
			}
			for _, r := range state.Records {
				if r.ID == id {
					if found && spec.Issuer != state.ID {
						return spec, errors.New("certificate ID ambiguous; specify --issuer")
					}
					spec = r.Spec
					spec.Issuer = state.ID
					found = true
				}
			}
		}
		if !found || spec.PolicySource == "nix" {
			m, err := loadPolicyManifest(getConfig(ctx))
			if err != nil {
				return spec, err
			}
			declared, ok := m.Certificates[id]
			if !ok {
				return spec, errors.New("certificate policy missing; supply --spec")
			}
			spec = declared
		}
	}
	if ctx.String("issuer") != "" {
		spec.Issuer = ctx.String("issuer")
	}
	if spec.Issuer == "" {
		return spec, errors.New("issuer required")
	}
	return spec, spec.Target.Validate()
}

func publicOutput(ctx *cli.Context, value any) error {
	if ctx.Bool("json") {
		return json.NewEncoder(ctx.App.Writer).Encode(value)
	}
	w := tabwriter.NewWriter(ctx.App.Writer, 0, 0, 2, ' ', 0)
	switch v := value.(type) {
	case []pki.State:
		fmt.Fprintln(w, "AUTHORITY\tACTIVE\tGENERATIONS\tCERTIFICATES\tSTATE")
		for _, state := range v {
			fmt.Fprintf(w, "%s\t%d\t%d\t%d\t%s\n", state.ID, state.Active, len(state.Generations), len(state.Records), authorityState(&state))
		}
	case *pki.State:
		fmt.Fprintf(w, "authority:\t%s\nactive:\t%d\nstate:\t%s\n", v.ID, v.Active, authorityState(v))
		fmt.Fprintln(w, "\nGENERATION\tISSUER\tEXPIRES\tRETIRED")
		for _, g := range v.Generations {
			issuer := "-"
			if g.Issuer != "" {
				issuer = fmt.Sprintf("%s/%d", g.Issuer, g.IssuerGeneration)
			}
			fmt.Fprintf(w, "%d\t%s\t%s\t%t\n", g.ID, issuer, g.NotAfter.Format(time.DateOnly), g.Retired)
		}
		if len(v.Records) > 0 {
			fmt.Fprintln(w)
			writeRecords(w, v.Records)
		}
	case []pki.Record:
		writeRecords(w, v)
	case *pki.Record:
		fmt.Fprintf(w, "certificate:\t%s\nissuer:\t%s/%d\nserial:\t%s\nexpires:\t%s\nstatus:\t%s\nfingerprint:\t%s\n",
			v.ID, v.Spec.Issuer, v.Generation, v.Serial, v.NotAfter.Format(time.DateOnly), recordState(v), v.Fingerprint)
	case map[string]bool:
		if v["valid"] {
			fmt.Fprintln(w, "valid")
		}
	case map[string]any:
		keys := make([]string, 0, len(v))
		for key := range v {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			fmt.Fprintf(w, "%s:\t%v\n", key, v[key])
		}
	default:
		return json.NewEncoder(ctx.App.Writer).Encode(value)
	}
	return w.Flush()
}

func writeRecords(w io.Writer, records []pki.Record) {
	fmt.Fprintln(w, "CERTIFICATE\tISSUER\tSERIAL\tEXPIRES\tSTATUS")
	for i := range records {
		r := &records[i]
		fmt.Fprintf(w, "%s\t%s/%d\t%s\t%s\t%s\n", r.ID, r.Spec.Issuer, r.Generation, r.Serial, r.NotAfter.Format(time.DateOnly), recordState(r))
	}
}

func authorityState(state *pki.State) string {
	var flags []string
	if state.Imported {
		flags = append(flags, "imported")
	}
	if state.Incomplete {
		flags = append(flags, "incomplete")
	}
	if len(state.Pending) > 0 {
		flags = append(flags, "pending")
	}
	if len(flags) == 0 {
		return "ok"
	}
	return strings.Join(flags, ",")
}

func recordState(r *pki.Record) string {
	switch {
	case r.RevokedAt != nil:
		return "revoked"
	case r.External:
		return "external"
	case r.Imported:
		return "imported"
	}
	return "issued"
}

func outputPEM(ctx *cli.Context, value string, private bool) error {
	if ctx.String("out") == "" {
		_, err := fmt.Fprint(ctx.App.Writer, value)
		return err
	}
	path := ctx.String("out")
	mode := os.FileMode(0o644)
	if private {
		mode = 0o600
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return atomicfile.Write(path, []byte(value), mode)
}

func pkiFlags() []cli.Flag {
	return []cli.Flag{
		&cli.PathFlag{Name: "spec", Usage: "public JSON policy (no Nix evaluation)"},
		&cli.StringFlag{Name: "issuer"},
		&cli.PathFlag{Name: "cert-file", Usage: "certificate PEM file, or - for stdin"},
		&cli.PathFlag{Name: "key-file", Usage: "private key PEM file, or - for stdin"},
		&cli.PathFlag{Name: "csr-file"},
		&cli.PathFlag{Name: "out"},
		&cli.IntFlag{Name: "generation"},
		&cli.IntFlag{Name: "validity-days", Value: 7},
		&cli.IntFlag{Name: "reason"},
		&cli.StringFlag{Name: "serial"},
		&cli.BoolFlag{Name: "force"},
		&cli.BoolFlag{Name: "json"},
		&cli.BoolFlag{Name: "check-key"},
		&cli.BoolFlag{Name: "private-key"},
		&cli.BoolFlag{Name: "chain"},
		&cli.BoolFlag{Name: "ca"},
		&cli.BoolFlag{Name: "acknowledge-untracked"},
	}
}

func pkiCmd() *cli.Command {
	root := &cli.Command{
		Name:   "pki",
		Usage:  "local authority, certificate, revocation and trust lifecycle",
		Before: func(ctx *cli.Context) error { return requireAdminSOPSConfig(getConfig(ctx)) },
	}
	ca := &cli.Command{Name: "ca", Usage: "manage named certificate authorities and signing generations"}
	for _, operation := range []commandOperation{
		{name: "create", mutation: true},
		{name: "import", mutation: true},
		{name: "list", mutation: false},
		{name: "show", mutation: false},
		{name: "renew", mutation: true},
		{name: "rotate", mutation: true},
		{name: "activate", mutation: true},
		{name: "retire", mutation: true},
		{name: "recover", mutation: true},
	} {
		verb := operation.name
		ca.Subcommands = append(ca.Subcommands, operationCommand(operation, pkiFlags(), func(ctx *cli.Context) error {
			store := pkiStore(getConfig(ctx))
			if verb == "list" {
				states, err := store.List()
				if err != nil {
					return err
				}
				return publicOutput(ctx, states)
			}
			id := ctx.Args().First()
			if id == "" {
				return errors.New("authority name is required")
			}
			if verb == "show" {
				state, err := store.Public(id)
				if err != nil {
					return err
				}
				return publicOutput(ctx, state)
			}
			var err error
			switch verb {
			case "create", "import":
				spec, e := authorityPolicy(ctx, id)
				if e != nil {
					return e
				}
				if verb == "create" {
					_, err = store.Create(id, spec)
				} else {
					cert, key, e := readImportInputs(ctx.String("cert-file"), ctx.String("key-file"))
					if e != nil {
						return e
					}
					_, err = store.ImportAuthority(id, spec, cert, key)
				}
			case "recover":
				_, err = store.Open(id)
			case "renew":
				spec, e := authorityPolicy(ctx, id)
				if e != nil {
					return e
				}
				_, err = store.RenewAuthority(id, spec)
			case "rotate":
				spec, e := authorityPolicy(ctx, id)
				if e != nil {
					return e
				}
				_, err = store.RotateAuthority(id, spec)
			case "activate":
				if ctx.Int("generation") < 1 {
					return errors.New("--generation required")
				}
				_, err = store.Activate(id, ctx.Int("generation"))
			case "retire":
				if ctx.Int("generation") < 1 {
					return errors.New("--generation required")
				}
				_, err = store.Retire(id, ctx.Int("generation"), ctx.Bool("acknowledge-untracked"))
			}
			if err != nil {
				return err
			}
			view, err := store.Public(id)
			if err != nil {
				return err
			}
			return publicOutput(ctx, view)
		}))
	}
	cert := &cli.Command{Name: "cert", Usage: "manage certificate bundles; renewal preserves keys and rotation replaces them"}
	for _, operation := range []commandOperation{
		{name: "ensure", mutation: true},
		{name: "issue", mutation: true},
		{name: "import", mutation: true},
		{name: "list", mutation: false},
		{name: "show", mutation: false},
		{name: "renew", mutation: true},
		{name: "rotate", mutation: true},
		{name: "revoke", mutation: true},
		{name: "verify", mutation: false},
		{name: "export", mutation: true},
	} {
		verb := operation.name
		cert.Subcommands = append(cert.Subcommands, operationCommand(operation, pkiFlags(), func(ctx *cli.Context) error {
			store := pkiStore(getConfig(ctx))
			if verb == "list" {
				states, err := store.List()
				if err != nil {
					return err
				}
				var records []pki.Record
				for _, state := range states {
					records = append(records, state.Records...)
				}
				return publicOutput(ctx, records)
			}
			id := ctx.Args().First()
			if verb == "revoke" && ctx.String("issuer") != "" && ctx.String("serial") != "" {
				_, err := store.Revoke(ctx.String("issuer"), id, ctx.String("serial"), ctx.Int("reason"))
				return err
			}
			if id == "" {
				return errors.New("certificate name required")
			}
			spec, err := certificatePolicy(ctx, id)
			if err != nil {
				return err
			}
			switch verb {
			case "ensure", "issue", "renew", "rotate":
				r, err := store.Certificate(id, spec, verb, ctx.Bool("force"))
				if err != nil {
					return err
				}
				return publicOutput(ctx, pki.PublicRecord(r))
			case "import":
				value, private, e := readImportInputs(ctx.String("cert-file"), ctx.String("key-file"))
				if e != nil {
					return e
				}
				r, err := store.ImportCertificate(id, spec, value, private)
				if err != nil {
					return err
				}
				return publicOutput(ctx, pki.PublicRecord(r))
			case "verify":
				if err := store.Verify(spec.Issuer, id, ctx.Bool("check-key")); err != nil {
					return err
				}
				return publicOutput(ctx, map[string]bool{"valid": true})
			case "revoke":
				_, err := store.Revoke(spec.Issuer, id, ctx.String("serial"), ctx.Int("reason"))
				return err
			case "show", "export":
				state, err := store.Public(spec.Issuer)
				if err != nil {
					return err
				}
				var record *pki.Record
				for i := range state.Records {
					if state.Records[i].ID == id {
						record = &state.Records[i]
					}
				}
				if record == nil {
					return errors.New("certificate not found")
				}
				if verb == "show" {
					return publicOutput(ctx, record)
				}
				value := record.Certificate
				if ctx.Bool("private-key") {
					state, err = store.Load(spec.Issuer)
					if err != nil {
						return err
					}
					for i := range state.Records {
						if state.Records[i].ID == id {
							value = state.Records[i].Key
						}
					}
					if value == "" {
						return errors.New("certificate has no stored private key")
					}
				} else if ctx.Bool("chain") {
					chain, err := store.Chain(spec.Issuer, record.Generation)
					if err != nil {
						return err
					}
					value += chain
				}
				return outputPEM(ctx, value, ctx.Bool("private-key"))
			}
			return nil
		}))
	}
	crl := &cli.Command{Name: "crl"}
	for _, operation := range []commandOperation{
		{name: "generate", mutation: true},
		{name: "show", mutation: false},
		{name: "verify", mutation: false},
	} {
		verb := operation.name
		crl.Subcommands = append(crl.Subcommands, operationCommand(operation, pkiFlags(), func(ctx *cli.Context) error {
			store := pkiStore(getConfig(ctx))
			id := ctx.Args().First()
			if id == "" {
				return errors.New("issuer required")
			}
			if verb == "verify" {
				return store.VerifyCRL(id, ctx.Int("generation"))
			}
			if verb == "generate" {
				value, err := store.CRL(id, ctx.Int("generation"), ctx.Int("validity-days"))
				if err != nil {
					return err
				}
				return outputPEM(ctx, value, false)
			}
			state, err := store.Public(id)
			if err != nil {
				return err
			}
			gen := ctx.Int("generation")
			if gen == 0 {
				gen = state.Active
			}
			value, ok := state.CRLs[gen]
			if !ok {
				return errors.New("CRL not generated")
			}
			return outputPEM(ctx, value, false)
		}))
	}
	trust := &cli.Command{Name: "trust"}
	for _, operation := range []commandOperation{
		{name: "export", mutation: true},
		{name: "status", mutation: false},
	} {
		verb := operation.name
		trust.Subcommands = append(trust.Subcommands, operationCommand(operation, pkiFlags(), func(ctx *cli.Context) error {
			ids := ctx.Args().Slice()
			if len(ids) == 0 {
				return errors.New("authority or declared trust-bundle names required")
			}
			store := pkiStore(getConfig(ctx))
			if len(ids) == 1 && !store.Exists(ids[0]) {
				m, err := loadPolicyManifest(getConfig(ctx))
				if err != nil {
					return err
				}
				var ok bool
				ids, ok = m.Trust[ids[0]]
				if !ok {
					return errors.New("unknown trust bundle")
				}
			}
			value, err := store.Trust(ids)
			if err != nil {
				return err
			}
			if verb == "export" {
				return outputPEM(ctx, value, false)
			}
			return publicOutput(ctx, map[string]any{"authorities": ids, "exportReady": true, "consumerRollout": "not observed"})
		}))
	}
	csr := &cli.Command{Name: "csr"}
	for _, operation := range []commandOperation{
		{name: "create", mutation: true},
		{name: "sign", mutation: true},
	} {
		verb := operation.name
		csr.Subcommands = append(csr.Subcommands, operationCommand(operation, pkiFlags(), func(ctx *cli.Context) error {
			id := ctx.Args().First()
			if id == "" {
				return errors.New("request name required")
			}
			store := pkiStore(getConfig(ctx))
			if ctx.Bool("ca") {
				spec, err := authorityPolicy(ctx, id)
				if err != nil {
					return err
				}
				var value string
				if verb == "create" {
					value, err = store.CreateAuthorityCSR(id, spec)
				} else {
					request, e := readOptional(ctx.String("csr-file"))
					if e != nil {
						return e
					}
					value, err = store.SignAuthorityCSR(id, spec, request)
				}
				if err != nil {
					return err
				}
				return outputPEM(ctx, value, false)
			}
			spec, err := certificatePolicy(ctx, id)
			if err != nil {
				return err
			}
			if verb == "create" {
				value, err := store.CreateCSR(id, spec)
				if err != nil {
					return err
				}
				return outputPEM(ctx, value, false)
			}
			value, err := readOptional(ctx.String("csr-file"))
			if err != nil {
				return err
			}
			record, err := store.SignCSR(id, spec, value)
			if err != nil {
				return err
			}
			return outputPEM(ctx, record.Certificate, false)
		}))
	}
	root.Subcommands = []*cli.Command{ca, cert, csr, crl, trust, {Name: "status", Before: optionsBeforeArgs, Flags: []cli.Flag{&cli.BoolFlag{Name: "json"}}, Action: func(ctx *cli.Context) error {
		states, err := pkiStore(getConfig(ctx)).List()
		if err != nil {
			return err
		}
		return publicOutput(ctx, states)
	}}}
	return root
}

func readImportInputs(certPath, keyPath string) (string, string, error) {
	if certPath == "-" && keyPath == "-" {
		return "", "", errors.New("only one import input may use stdin")
	}
	certificate, err := readOptional(certPath)
	if err != nil {
		return "", "", err
	}
	private, err := readOptional(keyPath)
	return certificate, private, err
}
