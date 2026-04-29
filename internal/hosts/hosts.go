package hosts

import (
	"os"
	"path/filepath"

	"git.tatikoma.dev/corpix/atlas/errors"
	"git.tatikoma.dev/corpix/atlas/log"
	"gopkg.in/yaml.v3"
)

func load(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]string{}, nil
		}
		return nil, errors.Wrapf(err, "read hosts file %s", path)
	}
	var m map[string]string
	if err := yaml.Unmarshal(data, &m); err != nil {
		return nil, errors.Wrapf(err, "parse hosts file %s", path)
	}
	if m == nil {
		m = map[string]string{}
	}
	return m, nil
}

func save(path string, m map[string]string) error {
	data, err := yaml.Marshal(m)
	if err != nil {
		return errors.Wrap(err, "marshal hosts")
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return errors.Wrapf(err, "create hosts dir")
	}

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return errors.Wrapf(err, "write hosts tmp file")
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return errors.Wrapf(err, "rename hosts tmp file")
	}
	return nil
}

func Get(path, machine string) (string, error) {
	m, err := load(path)
	if err != nil {
		return "", err
	}
	return m[machine], nil
}

func Set(path, machine, host string) error {
	log.Debug().Str("machine", machine).Str("host", host).Str("file", path).Msg("setting host")
	m, err := load(path)
	if err != nil {
		return err
	}
	m[machine] = host
	return save(path, m)
}
