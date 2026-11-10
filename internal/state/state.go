// Package state tracks the on-disk schema version of the per-flake state
// (hosts file, sops rules, secrets layout) so that `deploy migrate` can apply
// step migrations to bring an older repo forward.
package state

import (
	"encoding/json"
	"os"
	"path/filepath"

	"git.tatikoma.dev/corpix/atlas/errors"
	"git.tatikoma.dev/corpix/deploy/internal/atomicfile"
)

// TargetVersion is the schema version produced by the current deploy binary.
// Every committed migration step bumps this constant by one.
const TargetVersion = 1

const fileName = ".deploy.state"

// State is the on-disk JSON document at vars/.deploy.state.
type State struct {
	Version int `json:"version"`
}

// Path returns the absolute path to the state file inside the given flake dir.
func Path(flakeDir string) string {
	return filepath.Join(flakeDir, "vars", fileName)
}

// Load reads the state file. Missing files are reported as version 0 so a
// pre-state repo migrates cleanly.
func Load(flakeDir string) (*State, error) {
	path := Path(flakeDir)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &State{Version: 0}, nil
		}
		return nil, errors.Wrapf(err, "read %s", path)
	}
	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, errors.Wrapf(err, "parse %s", path)
	}
	return &s, nil
}

// Save writes the state file atomically with a trailing newline for clean diffs.
func Save(flakeDir string, s *State) error {
	path := Path(flakeDir)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return errors.Wrapf(err, "create dir for %s", path)
	}
	data, err := json.Marshal(s)
	if err != nil {
		return errors.Wrap(err, "marshal state")
	}
	data = append(data, '\n')
	return atomicfile.Write(path, data, 0o644)
}
