package cmd

import (
	"flag"
	"strings"
	"testing"

	"github.com/urfave/cli/v2"

	"git.tatikoma.dev/corpix/atlas/errors"
	"git.tatikoma.dev/corpix/deploy/internal/repolock"
)

func TestOperationPolicyDoesNotDependOnName(t *testing.T) {
	root := t.TempDir()
	cfg := &Config{FlakeDir: root}
	app := &cli.App{Metadata: map[string]interface{}{"deploy.config": cfg}}
	ctx := cli.NewContext(app, flag.NewFlagSet("test", flag.ContinueOnError), nil)
	release, err := repolock.Acquire(root)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	for _, mutation := range []bool{false, true} {
		called := false
		command := operationCommand(commandOperation{name: "unrelated-name", mutation: mutation}, nil, func(*cli.Context) error {
			called = true
			return nil
		})
		command.Name = "renamed"
		err := command.Action(ctx)
		if mutation {
			if err == nil || called {
				t.Fatal("mutation bypassed repository lock after rename")
			}
		} else if err != nil || !called {
			t.Fatalf("read-only operation acquired repository lock: %v", err)
		}
	}
}

func TestRepositoryMutationReleasesLockOnError(t *testing.T) {
	root := t.TempDir()
	app := &cli.App{Metadata: map[string]interface{}{"deploy.config": &Config{FlakeDir: root}}}
	ctx := cli.NewContext(app, flag.NewFlagSet("test", flag.ContinueOnError), nil)
	failure := errors.New("action failed")
	action := repositoryMutation(func(*cli.Context) error {
		if release, err := repolock.Acquire(root); err == nil {
			release()
			t.Fatal("action ran without repository lock")
		}
		return failure
	})
	if err := action(ctx); !errors.Is(err, failure) {
		t.Fatal(err)
	}
	release, err := repolock.Acquire(root)
	if err != nil {
		t.Fatalf("failed action retained lock: %v", err)
	}
	release()
}

func TestMutationCommandsDeclareRepositoryLock(t *testing.T) {
	root := t.TempDir()
	app := New()
	app.Metadata = map[string]interface{}{"deploy.config": &Config{FlakeDir: root}}
	ctx := cli.NewContext(app, flag.NewFlagSet("test", flag.ContinueOnError), nil)
	release, err := repolock.Acquire(root)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	for _, path := range []string{
		"init", "sync", "migrate", "host set",
		"machine init", "machine provision", "machine deploy",
		"key host", "key initrd", "key ensure", "key admin add", "key admin remove", "key session ensure", "key session remove",
		"group create", "group add", "group remove", "group delete",
		"secret set", "secret del", "secret update", "secret mv", "secret repair",
		"key yggdrasil ensure", "key yggdrasil rotate",
		"pki ca create", "pki ca import", "pki ca renew", "pki ca rotate", "pki ca activate", "pki ca retire", "pki ca recover",
		"pki cert ensure", "pki cert issue", "pki cert import", "pki cert renew", "pki cert rotate", "pki cert revoke", "pki cert export",
		"pki crl generate", "pki csr create", "pki csr sign", "pki trust export",
	} {
		t.Run(path, func(t *testing.T) {
			commands := app.Commands
			var selected *cli.Command
			for _, name := range strings.Fields(path) {
				selected = nil
				for _, command := range commands {
					if command.Name == name {
						selected = command
						break
					}
				}
				if selected == nil {
					t.Fatalf("command missing: %s", name)
				}
				commands = selected.Subcommands
			}
			if err := selected.Action(ctx); err == nil || !strings.Contains(err.Error(), "another deploy mutation") {
				t.Fatalf("mutation did not acquire lock: %v", err)
			}
		})
	}
}
