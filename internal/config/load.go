package config

import (
	"bytes"
	"fmt"
	"log/slog"
	"os"

	"gopkg.in/yaml.v3"
)

// Load reads, decodes (strict), defaults, and validates the YAML file at
// path. The returned Config is ready to hand to Compile.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)

	var c Config
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}

	applyDefaults(&c)
	if err := validate(&c); err != nil {
		return nil, fmt.Errorf("validate config %s: %w", path, err)
	}
	if c.Version == VersionV1Alpha1 {
		slog.Warn("config version is deprecated; schema is unchanged, update the version field",
			"path", path, "version", VersionV1Alpha1, "use", VersionV1Beta1)
	}
	return &c, nil
}
