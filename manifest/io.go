package manifest

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/dariofad/river/my_types"
	"gopkg.in/yaml.v3"
)

func Read(path string) (*Manifest, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}
	var m Manifest
	if err := yaml.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}
	return &m, nil
}

// WriteLegacyConfiguration atomically writes the exact JSON shape consumed by
// the existing simulator.
func WriteLegacyConfiguration(path string, config *my_types.Configuration) error {
	raw, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("encode simulator configuration: %w", err)
	}
	raw = append(raw, '\n')
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".river-config-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary simulator configuration: %w", err)
	}
	tmpPath := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpPath) }
	defer cleanup()
	if err := tmp.Chmod(0o644); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("set simulator configuration permissions: %w", err)
	}
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write simulator configuration: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close simulator configuration: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("replace simulator configuration: %w", err)
	}
	return nil
}

func Write(path string, m *Manifest) error {
	raw, err := yaml.Marshal(m)
	if err != nil {
		return fmt.Errorf("encode manifest: %w", err)
	}
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		return fmt.Errorf("write manifest: %w", err)
	}
	return nil
}
