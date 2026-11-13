package main

import (
	"os"

	"git.tatikoma.dev/corpix/deploy/cmd"
	"git.tatikoma.dev/corpix/deploy/internal/logging"
)

func main() {
	logging.Configure(os.Stderr, "deploy")
	app := cmd.New()
	if err := app.Run(os.Args); err != nil {
		os.Exit(1)
	}
}
