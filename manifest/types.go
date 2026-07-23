package manifest

// Manifest is the human-editable contract between river-manifest and River.
// It intentionally contains semantic identities only. Runtime addresses and
// uprobe offsets are rebuilt from the ELF each time River starts.
type Manifest struct {
	Version  uint32   `yaml:"version" json:"version"`
	Artifact Artifact `yaml:"artifact" json:"artifact"`
	Settings Settings `yaml:"settings" json:"settings"`
	Models   []Model  `yaml:"models" json:"models"`
}

type Artifact struct {
	Binary            string   `yaml:"binary" json:"binary"`
	BuildID           string   `yaml:"build_id" json:"build_id"`
	DescriptorSources []string `yaml:"descriptor_sources,omitempty" json:"descriptor_sources,omitempty"`
}

type Settings struct {
	Cycles      uint32 `yaml:"cycles" json:"cycles"`
	SampleEvery uint32 `yaml:"sample_every" json:"sample_every"`
}

type Model struct {
	Name           string    `yaml:"name" json:"name"`
	Enabled        bool      `yaml:"enabled" json:"enabled"`
	Hooks          HookRoles `yaml:"hooks" json:"hooks"`
	AvailableHooks []Hook    `yaml:"available_hooks" json:"available_hooks"`
	Inputs         []Data    `yaml:"inputs,omitempty" json:"inputs,omitempty"`
	Outputs        []Data    `yaml:"outputs,omitempty" json:"outputs,omitempty"`
	States         []Data    `yaml:"states,omitempty" json:"states,omitempty"`
}

type HookRoles struct {
	Write string `yaml:"write" json:"write"`
	Read  string `yaml:"read" json:"read"`
}

type Hook struct {
	ID       string `yaml:"id" json:"id"`
	Function string `yaml:"function" json:"function"`
	Phase    string `yaml:"phase" json:"phase"`
}

type Data struct {
	Name      string `yaml:"name" json:"name"`
	Path      string `yaml:"path" json:"path"`
	SID       string `yaml:"sid,omitempty" json:"sid,omitempty"`
	Category  string `yaml:"category,omitempty" json:"category,omitempty"`
	Type      string `yaml:"type" json:"type"`
	Enabled   bool   `yaml:"enabled" json:"enabled"`
	Supported bool   `yaml:"supported" json:"supported"`
	Reason    string `yaml:"reason,omitempty" json:"reason,omitempty"`
}

type RuntimePlan struct {
	Binary      string
	BuildID     string
	Cycles      uint32
	SampleEvery uint32
	Models      []RuntimeModel
	StateByName map[string]RuntimeData
}

type RuntimeModel struct {
	ID         uint32
	Name       string
	StepSymbol string
	WriteHook  RuntimeHook
	ReadHook   RuntimeHook
	Inputs     []RuntimeData
	Outputs    []RuntimeData
	States     []RuntimeData
}

type RuntimeHook struct {
	ID       string
	Symbol   string
	Function string
	Phase    string
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
