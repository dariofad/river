package manifest

import (
	"debug/elf"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestDecodeInstructionArchitectures(t *testing.T) {
	tests := []struct {
		name       string
		machine    elf.Machine
		code       []byte
		wantLen    int
		wantReturn bool
	}{
		{name: "x86 CET entry", machine: elf.EM_X86_64, code: []byte{0xf3, 0x0f, 0x1e, 0xfa}, wantLen: 4},
		{name: "x86 return", machine: elf.EM_X86_64, code: []byte{0xc3}, wantLen: 1, wantReturn: true},
		{name: "arm64 return", machine: elf.EM_AARCH64, code: []byte{0xc0, 0x03, 0x5f, 0xd6}, wantLen: 4, wantReturn: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			length, isReturn, err := decodeInstruction(test.machine, test.code)
			if err != nil {
				t.Fatal(err)
			}
			if length != test.wantLen || isReturn != test.wantReturn {
				t.Fatalf("got length=%d return=%v, want length=%d return=%v", length, isReturn, test.wantLen, test.wantReturn)
			}
		})
	}
}

func fixtureBinary(t *testing.T) string {
	t.Helper()
	code := `
class TestModel {
public:
    struct ExtU { double input; } TestModel_U;
    struct ExtY { double output; } TestModel_Y;
    struct State { double memory; } TestModel_DW;
    static double parameter;
    void step();
};
double TestModel::parameter = 1.0;
void TestModel::step() {
    TestModel_Y.output = TestModel_U.input + TestModel_DW.memory;
    // generated code continues after its externally visible outputs.
    TestModel_DW.memory = TestModel_Y.output;
}
static TestModel model;
int main() { model.step(); return 0; }
`
	return compileFixture(t, code)
}

func compileFixture(t *testing.T, code string) string {
	t.Helper()
	compiler, err := exec.LookPath("g++")
	if err != nil {
		t.Skip("g++ is required for ELF/DWARF manifest tests")
	}
	dir := t.TempDir()
	source := filepath.Join(dir, "model.cpp")
	binary := filepath.Join(dir, "model")
	if err := os.WriteFile(source, []byte(code), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(compiler, "-g", "-O0", "-fcf-protection=none", "-o", binary, source)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("compile fixture: %v\n%s", err, output)
	}
	return binary
}

func TestCompileLegacyFlattensMultipleModels(t *testing.T) {
	binary := compileFixture(t, `
class Alpha {
public:
    struct ExtU { double alphaIn; } Alpha_U;
    struct ExtY { double alphaOut; } Alpha_Y;
    void step();
};
class Beta {
public:
    struct ExtU { double betaIn; } Beta_U;
    struct ExtY { double betaOut; } Beta_Y;
    void step();
};
void Alpha::step() { Alpha_Y.alphaOut = Alpha_U.alphaIn; }
void Beta::step() { Beta_Y.betaOut = Beta_U.betaIn; }
static Alpha alpha;
static Beta beta;
int main() { alpha.step(); beta.step(); return 0; }
`)
	m, _, err := Generate(binary)
	if err != nil {
		t.Fatal(err)
	}
	for i := range m.Models {
		m.Models[i].Enabled = true
	}
	m.Settings.Cycles = 10
	m.Settings.TimerModel = "Beta"
	config, err := CompileLegacy(m, binary)
	if err != nil {
		t.Fatal(err)
	}
	if len(config.Writes) != 2 || len(config.Reads) != 2 {
		t.Fatalf("expected two flattened model groups: reads=%#v writes=%#v", config.Reads, config.Writes)
	}
	if config.Writes[0].Signals[0].Name != "alphaIn" || config.Writes[1].Signals[0].Name != "betaIn" {
		t.Fatalf("model order is not deterministic: %#v", config.Writes)
	}
	if config.TimerSymbol != "_ZN4Beta4stepEv" {
		t.Fatalf("timer symbol = %q, want Beta::step", config.TimerSymbol)
	}
}

func configuredManifest(t *testing.T) (*Manifest, string) {
	t.Helper()
	binary := fixtureBinary(t)
	m, _, err := Generate(binary)
	if err != nil {
		t.Fatal(err)
	}
	m.Settings.Cycles = 20
	return m, binary
}

func TestGenerateAndCompileLegacy(t *testing.T) {
	m, binary := configuredManifest(t)
	if got, want := len(m.Models), 1; got != want {
		t.Fatalf("models = %d, want %d", got, want)
	}
	model := m.Models[0]
	if model.Name != "TestModel" || m.Settings.TimerModel != "TestModel" {
		t.Fatalf("unexpected generated model/timer: %q/%q", model.Name, m.Settings.TimerModel)
	}
	if len(model.Hooks) != 2 || model.Hooks[0].ID != "step" || model.Hooks[0].Phase != "entry" || model.Hooks[0].Action != "write" || model.Hooks[1].ID != "step" || model.Hooks[1].Phase != "post_outputs" || model.Hooks[1].Action != "read" {
		t.Fatalf("unexpected generated hooks: %#v", model.Hooks)
	}
	if got, want := model.AvailableHooks, []Hook{{ID: "step"}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("available hooks = %#v, want %#v", got, want)
	}
	config, err := CompileLegacy(m, binary)
	if err != nil {
		t.Fatal(err)
	}
	if config.ModelPath != binary || config.TimerSymbol != "_ZN9TestModel4stepEv" {
		t.Fatalf("unexpected target: %#v", config)
	}
	if config.NofCycles != "20" || config.MinorToMajorRatio != "1" {
		t.Fatalf("unexpected settings: %#v", config)
	}
	if len(config.Writes) != 1 || len(config.Writes[0].Signals) != 1 {
		t.Fatalf("unexpected writes: %#v", config.Writes)
	}
	if len(config.Reads) != 1 || len(config.Reads[0].Signals) != 2 {
		t.Fatalf("unexpected reads: %#v", config.Reads)
	}
	if config.Reads[0].Offset == "0" {
		t.Fatalf("post-output hook was not resolved to an instruction after entry: %#v", config.Reads[0])
	}
	if config.Reads[0].Signals[0].Name != "input" || config.Reads[0].Signals[1].Name != "output" {
		t.Fatalf("inputs must precede outputs in reads: %#v", config.Reads[0].Signals)
	}
	if config.Writes[0].Signals[0].Addr == config.Reads[0].Signals[1].Addr {
		t.Fatal("input and output addresses must differ")
	}
	address, err := strconv.ParseUint(config.Writes[0].Signals[0].Addr, 16, 64)
	if err != nil || address < 0x1000 {
		t.Fatalf("instance field lowered to member offset instead of ELF address: %q", config.Writes[0].Signals[0].Addr)
	}
}

func TestFixedStages(t *testing.T) {
	for _, test := range []struct {
		name string
		src  string
		want uint32
		ok   bool
	}{
		{"discrete", "", 0, false},
		{"ode1", "void rt_ertODEUpdateContinuousStates() { real_T rt_ODE1_A[1]; } this->step();", 1, true},
		{"ode2", "void rt_ertODEUpdateContinuousStates() { real_T rt_ODE2_A[2]; } this->step();", 2, true},
		{"ode3", "void rt_ertODEUpdateContinuousStates() { real_T rt_ODE3_A[3]; } this->step(); this->step();", 3, true},
		{"ode4", "void rt_ertODEUpdateContinuousStates() { real_T rt_ODE4_A[4]; } this->step(); this->step(); this->step();", 4, true},
		{"ode5", "void rt_ertODEUpdateContinuousStates() { real_T rt_ertODEUpdateContinuousStates(); real_T rt_ODE5_A[6]; } this->step(); this->step(); this->step(); this->step(); this->step();", 6, true},
		{"ode8", "void rt_ertODEUpdateContinuousStates() { real_T rt_ODE8_A[13]; } this->step(); this->step(); this->step(); this->step(); this->step(); this->step(); this->step(); this->step(); this->step(); this->step(); this->step(); this->step();", 13, true},
		{"implicit", "void rt_ertODEUpdateContinuousStates() { real_T rt_ODE14x_A[3]; } this->step(); this->step();", 0, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, ok := fixedStages(strings.Split(test.src, "\n"))
			if got != test.want || ok != test.ok {
				t.Fatalf("fixedStages() = (%d, %v), want (%d, %v)", got, ok, test.want, test.ok)
			}
		})
	}
}

func TestPostOutputOffset(t *testing.T) {
	source := []string{"void Model::step() {", "Model_Y.a = 1;", "Model_Y.b = 2;", "log();", "}"}
	lines := []sourceLine{{line: 2, address: 100}, {line: 3, address: 110}, {line: 4, address: 120}}
	outputs := []Data{{Name: "a", Path: "Model.Model_Y.a"}, {Name: "b", Path: "Model.Model_Y.b"}}
	if got, ok := postOutputOffset(source, lines, elf.Symbol{Value: 100}, outputs); !ok || got != 20 {
		t.Fatalf("postOutputOffset() = (%d, %v), want (20, true)", got, ok)
	}
}

func TestCompileLegacyReportsCompatibilityProblems(t *testing.T) {
	m, binary := configuredManifest(t)
	m.Settings.Cycles = 0
	m.Settings.TimerModel = "missing"
	m.Models[0].Hooks[0].Phase = "invalid"
	m.Models[0].Inputs[0].Name = m.Models[0].Outputs[0].Name
	readHook := m.Models[0].Hooks[1].ID
	m.Models[0].Hooks = append(m.Models[0].Hooks, HookSelection{ID: readHook, Phase: m.Models[0].Hooks[1].Phase, Action: "read", Data: []string{m.Models[0].States[0].Path}})
	_, err := CompileLegacy(m, binary)
	if err == nil {
		t.Fatal("expected compatibility error")
	}
	message := err.Error()
	for _, want := range []string{
		"settings.cycles must be at least 1",
		"unknown hook phase \"invalid\"",
		"selects hook \"" + readHook + "\" at post_outputs for read more than once",
		"duplicate read signal name",
		"timer model \"missing\" is not enabled",
	} {
		if !strings.Contains(message, want) {
			t.Errorf("error %q does not contain %q", message, want)
		}
	}
}

func TestCompileLegacySupportsIndependentHookSelectionsAndStates(t *testing.T) {
	m, binary := configuredManifest(t)
	model := &m.Models[0]
	model.Hooks = []HookSelection{
		{ID: "step", Phase: "entry", Action: "write", Data: []string{model.Inputs[0].Path, model.States[0].Path}},
		{ID: "step", Phase: "entry", Action: "read", Data: []string{model.States[0].Path}},
		{ID: "step", Phase: "return", Action: "read", Data: []string{model.Inputs[0].Path, model.Outputs[0].Path}},
	}
	config, err := CompileLegacy(m, binary)
	if err != nil {
		t.Fatal(err)
	}
	if len(config.Writes) != 1 || len(config.Writes[0].Signals) != 2 {
		t.Fatalf("unexpected writes: %#v", config.Writes)
	}
	if len(config.Reads) != 2 || config.Reads[0].Offset != "0" || len(config.Reads[1].Signals) != 2 {
		t.Fatalf("unexpected reads: %#v", config.Reads)
	}
}

func TestCompileLegacySupportsCustomHookOffset(t *testing.T) {
	m, binary := configuredManifest(t)
	baseline, err := CompileLegacy(m, binary)
	if err != nil {
		t.Fatal(err)
	}
	offset, err := strconv.ParseUint(baseline.Reads[0].Offset, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	model := &m.Models[0]
	model.Hooks = []HookSelection{{ID: "step", Phase: "custom", Offset: &offset, Action: "read", Data: []string{model.Outputs[0].Path}}}
	config, err := CompileLegacy(m, binary)
	if err != nil {
		t.Fatal(err)
	}
	if len(config.Reads) != 1 || config.Reads[0].Offset != baseline.Reads[0].Offset {
		t.Fatalf("custom hook was not lowered at its requested offset: %#v", config.Reads)
	}

	model.Hooks[0].Offset = nil
	if _, err := CompileLegacy(m, binary); err == nil || !strings.Contains(err.Error(), "custom phase requires an offset") {
		t.Fatalf("expected missing custom offset error, got %v", err)
	}

	invalidOffset := uint64(1 << 30)
	model.Hooks[0].Offset = &invalidOffset
	if _, err := CompileLegacy(m, binary); err == nil || !strings.Contains(err.Error(), "not an instruction boundary") {
		t.Fatalf("expected invalid custom offset error, got %v", err)
	}

	model.Hooks[0].Phase = "entry"
	model.Hooks[0].Offset = &offset
	if _, err := CompileLegacy(m, binary); err == nil || !strings.Contains(err.Error(), "offset is only valid for the custom phase") {
		t.Fatalf("expected non-custom offset error, got %v", err)
	}
}

func TestCompileLegacySupportsStaticStates(t *testing.T) {
	m, binary := configuredManifest(t)
	model := &m.Models[0]
	var parameter Data
	for _, state := range model.States {
		if state.Category == "parameter" && state.Supported {
			parameter = state
			break
		}
	}
	if parameter.Path == "" {
		t.Fatalf("static parameter was not discovered: %#v", model.States)
	}
	model.Hooks = []HookSelection{{ID: "step", Phase: "return", Action: "read", Data: []string{parameter.Path}}}
	config, err := CompileLegacy(m, binary)
	if err != nil {
		t.Fatal(err)
	}
	if len(config.Reads) != 1 || len(config.Reads[0].Signals) != 1 || config.Reads[0].Signals[0].Addr == "" {
		t.Fatalf("static state was not lowered: %#v", config.Reads)
	}
}

func TestCompileLegacyRejectsInvalidHookSelection(t *testing.T) {
	m, binary := configuredManifest(t)
	model := &m.Models[0]
	model.Hooks = append(model.Hooks,
		HookSelection{ID: "step", Phase: "entry", Action: "write", Data: []string{model.Inputs[0].Path}},
		HookSelection{ID: "missing", Phase: "return", Action: "read", Data: []string{model.Outputs[0].Path}},
		HookSelection{ID: "step", Phase: "return", Action: "invalid", Data: []string{model.Outputs[0].Path}},
	)
	_, err := CompileLegacy(m, binary)
	if err == nil {
		t.Fatal("expected invalid selection errors")
	}
	for _, want := range []string{"selects hook \"step\" at entry for write more than once", "unknown hook \"missing\"", "invalid action \"invalid\""} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err, want)
		}
	}
}

func TestCompileLegacyRejectsStaleBuild(t *testing.T) {
	m, binary := configuredManifest(t)
	m.Artifact.BuildID = "sha256:stale"
	if _, err := CompileLegacy(m, binary); err == nil || !strings.Contains(err.Error(), "build_id") {
		t.Fatalf("expected stale build error, got %v", err)
	}
}

func TestCompileLegacyAcceptsMatchingBinaryAtNewPath(t *testing.T) {
	m, binary := configuredManifest(t)
	raw, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	moved := filepath.Join(t.TempDir(), "relocated-model")
	if err := os.WriteFile(moved, raw, 0o755); err != nil {
		t.Fatal(err)
	}
	config, err := CompileLegacy(m, moved)
	if err != nil {
		t.Fatal(err)
	}
	if config.ModelPath != moved {
		t.Fatalf("MODEL_PATH = %q, want explicit binary %q", config.ModelPath, moved)
	}
}

func TestWriteLegacyConfigurationIsSimulatorCompatible(t *testing.T) {
	m, binary := configuredManifest(t)
	config, err := CompileLegacy(m, binary)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if err := WriteLegacyConfiguration(path, config); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"MODEL_PATH", "TIMER_SYMBOL", "MINOR_TO_MAJOR_RATIO", "NOF_CYCLES", "READS", "WRITES", "SIGNALS", "ADDR"} {
		if !strings.Contains(string(raw), `"`+key+`"`) {
			t.Errorf("JSON is missing legacy key %q: %s", key, raw)
		}
	}
}
