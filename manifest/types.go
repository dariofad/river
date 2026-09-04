package manifest

// Manifest is the human-editable contract between river-manifest and River.
// It keeps data identities semantic while retaining user-selected uprobe
// offsets. ELF addresses and symbols are resolved when it is compiled to JSON.
type Manifest struct {
	Version  uint32   `yaml:"version" json:"version"`
	Artifact Artifact `yaml:"artifact" json:"artifact"`
	Settings Settings `yaml:"settings" json:"settings"`
	Models   []Model  `yaml:"models" json:"models"`
}

type Artifact struct {
	Binary  string `yaml:"binary" json:"binary"`
	BuildID string `yaml:"build_id" json:"build_id"`
}

type Settings struct {
	Cycles      uint32 `yaml:"cycles" json:"cycles"`
	SampleEvery uint32 `yaml:"sample_every" json:"sample_every"`
	TimerModel  string `yaml:"timer_model" json:"timer_model"`
}

type Model struct {
	Name           string          `yaml:"name" json:"name"`
	Enabled        bool            `yaml:"enabled" json:"enabled"`
	Hooks          []HookSelection `yaml:"hooks" json:"hooks"`
	AvailableHooks []Hook          `yaml:"available_hooks" json:"available_hooks"`
	Inputs         []Data          `yaml:"inputs,omitempty" json:"inputs,omitempty"`
	Outputs        []Data          `yaml:"outputs,omitempty" json:"outputs,omitempty"`
	States         []Data          `yaml:"states,omitempty" json:"states,omitempty"`
}

// HookSelection selects one model-local available hook and the data to attach
// to it. A hook may be selected once for each action.
type HookSelection struct {
	ID     string   `yaml:"id" json:"id"`
	Action string   `yaml:"action" json:"action"`
	Data   []string `yaml:"data" json:"data"`
}

type Hook struct {
	ID       string `yaml:"id" json:"id"`
	Function string `yaml:"function" json:"function"`
	Phase    string `yaml:"phase" json:"phase"`
	Offset   uint64 `yaml:"offset" json:"offset"`
}

type Data struct {
	Name      string `yaml:"name" json:"name"`
	Path      string `yaml:"path" json:"path"`
	Category  string `yaml:"category,omitempty" json:"category,omitempty"`
	Type      string `yaml:"type" json:"type"`
	Supported bool   `yaml:"supported" json:"supported"`
	Reason    string `yaml:"reason,omitempty" json:"reason,omitempty"`
}

type RuntimeData struct {
	ID       uint32
	ModelID  uint32
	Name     string
	Path     string
	Category string
	Type     PrimitiveType
	Base     BaseKind
	Offset   int64
}

type BaseKind uint8

const (
	BaseThis BaseKind = iota + 1
	BaseELF
)

type PrimitiveType struct {
	Name     string
	Size     uint8
	Signed   bool
	Floating bool
	Boolean  bool
}
