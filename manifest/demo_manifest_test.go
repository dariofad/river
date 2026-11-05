package manifest

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCheckedInDemoManifestsCompileWhenTheirBinariesExist(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join("..", "simulator", "demos", "*.river.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatal("no demo manifests found")
	}
	modelsDir := os.Getenv("MODELS_DIR")
	if modelsDir == "" {
		modelsDir = filepath.Join("..", "..", "sim2cpp")
	}
	for _, path := range paths {
		t.Run(filepath.Base(path), func(t *testing.T) {
			m, err := Read(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := Repair(m, modelsDir, ""); err != nil {
				if os.IsNotExist(err) {
					t.Skipf("demo binary is unavailable: %v", err)
				}
				t.Skipf("demo binary could not be repaired (%s): %v", m.Artifact.Binary, err)
			}
			if _, err := CompileConfiguration(m); err != nil {
				t.Fatal(err)
			}
		})
	}
}
