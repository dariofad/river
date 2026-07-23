package manifest

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// DescriptorExport is the portable representation produced by the bundled
// MATLAB bridge from codedescriptor.dmr.
type DescriptorExport struct {
	ModelName string           `json:"model_name"`
	Data      []DescriptorData `json:"data"`
}

type DescriptorData struct {
	Category       string `json:"category"`
	GraphicalName  string `json:"graphical_name"`
	SID            string `json:"sid"`
	Implementation string `json:"implementation"`
	Unit           string `json:"unit"`
}

func EnrichDescriptor(m *Manifest, path string) error {
	return EnrichDescriptors(m, []string{path})
}

// EnrichDescriptors merges Code Descriptor exports into their corresponding
// ELF-discovered models. Each descriptor must identify a distinct model.
func EnrichDescriptors(m *Manifest, paths []string) error {
	exports := make([]DescriptorExport, 0, len(paths))
	seenModels := make(map[string]string, len(paths))
	for _, path := range paths {
		exported, err := readDescriptorExport(path)
		if err != nil {
			return err
		}
		if previous, duplicate := seenModels[exported.ModelName]; duplicate {
			return fmt.Errorf("descriptor %q duplicates model %q already provided by %q", path, exported.ModelName, previous)
		}
		seenModels[exported.ModelName] = path
		exports = append(exports, exported)
	}
	for _, exported := range exports {
		if err := enrichDescriptor(m, exported); err != nil {
			return err
		}
	}
	return nil
}

func readDescriptorExport(path string) (DescriptorExport, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return DescriptorExport{}, fmt.Errorf("read descriptor export: %w", err)
	}
	var exported DescriptorExport
	if err := json.Unmarshal(raw, &exported); err != nil {
		return DescriptorExport{}, fmt.Errorf("parse descriptor export: %w", err)
	}
	return exported, nil
}

func enrichDescriptor(m *Manifest, exported DescriptorExport) error {
	var model *Model
	for i := range m.Models {
		if m.Models[i].Name == exported.ModelName {
			model = &m.Models[i]
			break
		}
	}
	if model == nil {
		return fmt.Errorf("descriptor model %q was not discovered in the ELF", exported.ModelName)
	}
	for _, semantic := range exported.Data {
		items := descriptorCategory(model, semantic.Category)
		if items == nil {
			continue
		}
		matched := -1
		for i := range *items {
			candidate := &(*items)[i]
			if equalIdentifier(candidate.Name, semantic.Implementation) || equalIdentifier(candidate.Name, semantic.GraphicalName) || strings.HasSuffix(candidate.Path, "."+semantic.Implementation) {
				if matched >= 0 {
					return fmt.Errorf("descriptor item %q ambiguously matches multiple ELF fields", semantic.GraphicalName)
				}
				matched = i
			}
		}
		if matched < 0 {
			name := semantic.Implementation
			if name == "" {
				name = semantic.GraphicalName
			}
			*items = append(*items, Data{
				Name:      name,
				Path:      exported.ModelName + "." + name,
				SID:       semantic.SID,
				Category:  semantic.Category,
				Enabled:   false,
				Supported: false,
				Reason:    "Code Descriptor item has no addressable DWARF implementation",
			})
			continue
		}
		item := &(*items)[matched]
		item.SID = semantic.SID
	}
	return nil
}

func descriptorCategory(model *Model, category string) *[]Data {
	switch strings.ToLower(category) {
	case "inports", "input", "inputs":
		return &model.Inputs
	case "outports", "output", "outputs":
		return &model.Outputs
	case "internaldata", "states", "parameters", "datastores":
		return &model.States
	default:
		return nil
	}
}

func equalIdentifier(a, b string) bool {
	return b != "" && strings.EqualFold(strings.ReplaceAll(a, "_", ""), strings.ReplaceAll(b, "_", ""))
}
