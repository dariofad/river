package manifest

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func toyBinary(t *testing.T) string {
	t.Helper()
	path, err := filepath.Abs(filepath.Join("..", "..", "sim2cpp", "ToyModel", "Simulink2Code_ert_rtw", "Simulink2Code"))
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func TestGenerateAndCompile(t *testing.T) {
	m, err := Generate(toyBinary(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Models) != 1 || m.Models[0].Name != "Simulink2Code" {
		t.Fatalf("unexpected models: %#v", m.Models)
	}
	if got := len(m.Models[0].Inputs); got != 2 {
		t.Fatalf("got %d inputs, want 2", got)
	}
	if got := len(m.Models[0].Outputs); got != 1 {
		t.Fatalf("got %d outputs, want 1", got)
	}
	plan, err := Compile(m)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Models) != 1 || len(plan.Models[0].Inputs) != 2 || len(plan.Models[0].Outputs) != 1 {
		t.Fatalf("unexpected runtime plan: %#v", plan.Models)
	}
	if plan.Models[0].Inputs[0].Offset == plan.Models[0].Inputs[1].Offset {
		t.Fatal("input member offsets must differ")
	}
}

func TestCompileRejectsStaleBuild(t *testing.T) {
	m, err := Generate(toyBinary(t))
	if err != nil {
		t.Fatal(err)
	}
	m.Artifact.BuildID = "sha256:stale"
	if _, err := Compile(m); err == nil {
		t.Fatal("expected stale build ID error")
	}
}

func TestMultipleModels(t *testing.T) {
	binary, err := filepath.Abs(filepath.Join("..", "..", "sim2cpp", "DualACC", "dualACC"))
	if err != nil {
		t.Fatal(err)
	}
	m, err := Generate(binary)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Models) != 2 {
		t.Fatalf("got %d models, want leadCar and egoCar", len(m.Models))
	}
}

func TestEnrichMultipleDescriptors(t *testing.T) {
	binary, err := filepath.Abs(filepath.Join("..", "..", "sim2cpp", "DualACC", "dualACC"))
	if err != nil {
		t.Fatal(err)
	}
	m, err := Generate(binary)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Models) != 2 {
		t.Fatalf("got %d models, want 2", len(m.Models))
	}
	paths := make([]string, 0, len(m.Models))
	for _, model := range m.Models {
		category := "inputs"
		items := model.Inputs
		if len(items) == 0 {
			category = "outputs"
			items = model.Outputs
		}
		if len(items) == 0 {
			t.Fatalf("model %s has no addressable data for descriptor matching", model.Name)
		}
		export := DescriptorExport{
			ModelName: model.Name,
			Data: []DescriptorData{{
				Category:       category,
				GraphicalName:  "graphical_" + items[0].Name,
				Implementation: items[0].Name,
				SID:            model.Name + ":test",
			}},
		}
		raw, err := json.Marshal(export)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), model.Name+".json")
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, path)
	}
	if err := EnrichDescriptors(m, paths); err != nil {
		t.Fatal(err)
	}
	for _, model := range m.Models {
		items := model.Inputs
		if len(items) == 0 {
			items = model.Outputs
		}
		if got, want := items[0].SID, model.Name+":test"; got != want {
			t.Fatalf("model %s SID = %q, want %q", model.Name, got, want)
		}
	}
	if err := EnrichDescriptors(m, []string{paths[0], paths[0]}); err == nil {
		t.Fatal("expected duplicate model descriptor error")
	}
}

func TestStaticParameterUsesELFRelativeBase(t *testing.T) {
	binary, err := filepath.Abs(filepath.Join("..", "..", "sim2cpp", "AbstractFuelControl_M1_grt_rtw", "fuel_control"))
	if err != nil {
		t.Fatal(err)
	}
	m, err := Generate(binary)
	if err != nil {
		t.Fatal(err)
	}
	enabled := false
	for i := range m.Models[0].States {
		if m.Models[0].States[i].Category == "parameter" && m.Models[0].States[i].Supported {
			m.Models[0].States[i].Enabled = true
			enabled = true
			break
		}
	}
	if !enabled {
		t.Fatal("no static scalar parameter discovered")
	}
	plan, err := Compile(m)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Models[0].States) != 1 || plan.Models[0].States[0].Base != BaseELF {
		t.Fatalf("unexpected static state descriptor: %#v", plan.Models[0].States)
	}
}

func TestStaticParametersHaveUniquePaths(t *testing.T) {
	binary, err := filepath.Abs(filepath.Join("..", "..", "sim2cpp", "AbstractFuelControl_M1_grt_rtw", "fuel_control"))
	if err != nil {
		t.Fatal(err)
	}
	m, err := Generate(binary)
	if err != nil {
		t.Fatal(err)
	}
	seen := make(map[string]bool)
	for _, state := range m.Models[0].States {
		if state.Category != "parameter" {
			continue
		}
		if seen[state.Path] {
			t.Fatalf("duplicate static parameter path %q", state.Path)
		}
		seen[state.Path] = true
	}
}
