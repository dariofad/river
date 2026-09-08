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
	for _, path := range paths {
		t.Run(filepath.Base(path), func(t *testing.T) {
			m, err := Read(path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(m.Artifact.Binary); os.IsNotExist(err) {
				t.Skipf("demo binary is unavailable: %s", m.Artifact.Binary)
			}
			if _, err := CompileConfiguration(m); err != nil {
				t.Fatal(err)
			}
		})
	}
}
