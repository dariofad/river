package manifest

import (
	"fmt"
	"strconv"

	"gopkg.in/yaml.v3"
)

// HexUint64 keeps editable binary locations unambiguous in YAML.
type HexUint64 uint64

func (v HexUint64) MarshalYAML() (interface{}, error) {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int", Value: fmt.Sprintf("0x%x", uint64(v))}, nil
}

func (v *HexUint64) UnmarshalYAML(node *yaml.Node) error {
	if node.Tag == "!!int" {
		var raw uint64
		if err := node.Decode(&raw); err != nil {
			return err
		}
		*v = HexUint64(raw)
		return nil
	}
	parsed, err := strconv.ParseUint(node.Value, 0, 64)
	if err != nil {
		return err
	}
	*v = HexUint64(parsed)
	return nil
}

// Manifest is the human-editable contract between river-manifest and River.
// It keeps data identities and hook intent semantic. ELF symbols, addresses,
// and uprobe offsets are resolved only when it is compiled to JSON.
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
	Timer       Timer  `yaml:"timer" json:"timer"`
}

// Timer identifies the model hook that advances the simulation clock.
type Timer struct {
	Model string `yaml:"model" json:"model"`
	Hook  string `yaml:"hook" json:"hook"`
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

// HookSelection selects one model-local available function, a semantic phase,
// and the data to attach. A function/phase pair may be selected once per
// action, except custom selections which are distinguished by offset. Offset
// is only valid for the custom phase.
type HookSelection struct {
	ID     string     `yaml:"id" json:"id"`
	Phase  string     `yaml:"phase" json:"phase"`
	Offset *HexUint64 `yaml:"offset,omitempty" json:"offset,omitempty"`
	Action string     `yaml:"action" json:"action"`
	Data   []string   `yaml:"data" json:"data"`
}

type Hook struct {
	ID     string `yaml:"id" json:"id"`
	Symbol string `yaml:"symbol,omitempty" json:"symbol,omitempty"`
}

type Data struct {
	Name      string `yaml:"name" json:"name"`
	Path      string `yaml:"path" json:"path"`
	Category  string `yaml:"category,omitempty" json:"category,omitempty"`
	Type      string `yaml:"type" json:"type"`
	Supported bool   `yaml:"supported" json:"supported"`
	Reason    string `yaml:"reason,omitempty" json:"reason,omitempty"`
	// Address makes this a user-defined datum. It is an ELF virtual address,
	// resolved directly at compilation instead of through DWARF discovery.
	Address *HexUint64 `yaml:"address,omitempty" json:"address,omitempty"`
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
