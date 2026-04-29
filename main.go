package main

import (
	"os"

	_ "git.tatikoma.dev/corpix/atlas/log"
	"git.tatikoma.dev/corpix/deploy/cmd"
)

func main() {
	app := cmd.New()
	if err := app.Run(os.Args); err != nil {
		os.Exit(1)
	}
}
