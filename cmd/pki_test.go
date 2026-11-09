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
