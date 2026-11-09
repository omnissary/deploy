package cmd

import (
	"flag"
	"github.com/urfave/cli/v2"
	"os"
	"path/filepath"
	"testing"
)

func TestManualAuthorityPolicyDoesNotEvaluateNix(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ca.json")
	os.WriteFile(path, []byte(`{"subject":"manual-root","algorithm":"p384","validityDays":730}`), 0600)
	set := flag.NewFlagSet("test", flag.ContinueOnError)
	set.String("spec", path, "")
	ctx := cli.NewContext(&cli.App{}, set, nil)
	spec, err := authorityPolicy(ctx, "root")
	if err != nil || spec.Subject != "manual-root" || spec.Algorithm != "p384" || spec.ValidityDays != 730 {
		t.Fatal(spec, err)
	}
}

func TestLifecycleRejectsOptionsAfterResourceName(t *testing.T) {
	command := operationCommand(commandOperation{name: "rotate", mutation: true}, nil, func(*cli.Context) error { return nil })
	set := flag.NewFlagSet("test", flag.ContinueOnError)
	if err := set.Parse([]string{"client", "--force"}); err != nil {
		t.Fatal(err)
	}
	ctx := cli.NewContext(&cli.App{}, set, nil)
	if err := command.Before(ctx); err == nil {
		t.Fatal("silently ignored trailing force flag")
	}
}
