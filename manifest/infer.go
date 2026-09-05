package manifest

import (
	"debug/dwarf"
	"debug/elf"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var odeStages = regexp.MustCompile(`rt_ODE[0-9]+_A\[([0-9]+)\]`)

// inferSemanticDefaults uses generated source named by DWARF to select a
// post-output instruction and to recognize fixed-stage explicit solvers.
func inferSemanticDefaults(binary string, m *Manifest, discovered *discovery) []string {
	ef, err := elf.Open(binary)
	if err != nil {
		return []string{fmt.Sprintf("semantic inference unavailable: %v", err)}
	}
	defer ef.Close()
	dw, err := ef.DWARF()
	if err != nil {
		return []string{"semantic inference unavailable: binary has no DWARF"}
	}
	var warnings []string
	ratio := uint32(0)
	for i := range m.Models {
		model := &m.Models[i]
		dm := discovered.Models[model.Name]
		if dm == nil {
			warnings = append(warnings, fmt.Sprintf("model %q: was not discovered", model.Name))
			continue
		}
		symbol, err := findFunctionSymbol(ef, dm.Funcs["step"])
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("model %q: %v", model.Name, err))
			continue
		}
		source, lines, err := functionSource(dw, symbol, model.Outputs)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("model %q: using terminal return (%v)", model.Name, err))
			continue
		}
		if _, ok := postOutputOffset(source, lines, symbol, model.Outputs); ok {
			for h := range model.Hooks {
				if model.Hooks[h].ID == "step" && model.Hooks[h].Phase == "return" && model.Hooks[h].Action == "read" {
					model.Hooks[h].Phase = "post_outputs"
				}
			}
		} else {
			warnings = append(warnings, fmt.Sprintf("model %q: no post-output source site; using terminal return", model.Name))
		}
		if model.Name != m.Settings.TimerModel {
			continue
		}
		stages, ok := fixedStages(source)
		if !ok {
			warnings = append(warnings, fmt.Sprintf("model %q: solver cadence not proven; using sample_every: 1", model.Name))
			continue
		}
		ratio = stages
	}
	if ratio > 0 {
		m.Settings.SampleEvery = ratio
	}
	return warnings
}

type sourceLine struct {
	file    string
	line    int
	address uint64
}

func functionSource(dw *dwarf.Data, symbol elf.Symbol, outputs []Data) ([]string, []sourceLine, error) {
	r := dw.Reader()
	var matches []sourceLine
	for {
		e, err := r.Next()
		if err != nil {
			return nil, nil, err
		}
		if e == nil {
			break
		}
		if e.Tag != dwarf.TagCompileUnit {
			continue
		}
		compDir, _ := e.Val(dwarf.AttrCompDir).(string)
		lr, err := dw.LineReader(e)
		if err != nil {
			continue
		}
		var le dwarf.LineEntry
		for lr.Next(&le) == nil {
			if le.Address >= symbol.Value && le.Address < symbol.Value+symbol.Size && le.File != nil {
				path := le.File.Name
				if !filepath.IsAbs(path) && compDir != "" {
					path = filepath.Join(compDir, path)
				}
				matches = append(matches, sourceLine{path, le.Line, le.Address})
			}
		}
	}
	if len(matches) == 0 {
		return nil, nil, fmt.Errorf("no source lines for step")
	}
	byFile := make(map[string][]sourceLine)
	for _, line := range matches {
		byFile[line.file] = append(byFile[line.file], line)
	}
	paths := make([]string, 0, len(byFile))
	for path := range byFile {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		fileLines := byFile[path]
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		source := strings.Split(string(raw), "\n")
		if outputAssignmentLine(source, fileLines, outputs) != 0 {
			return source, fileLines, nil
		}
	}
	return nil, nil, fmt.Errorf("no generated source with output assignments")
}

func postOutputOffset(source []string, lines []sourceLine, symbol elf.Symbol, outputs []Data) (uint64, bool) {
	last := outputAssignmentLine(source, lines, outputs)
	if last == 0 {
		return 0, false
	}
	for _, line := range lines {
		if line.line > last && line.address >= symbol.Value {
			return line.address - symbol.Value, true
		}
	}
	return 0, false
}

func outputAssignmentLine(source []string, lines []sourceLine, outputs []Data) int {
	first, limit := 0, 0
	for _, line := range lines {
		if first == 0 || line.line < first {
			first = line.line
		}
		if line.line > limit {
			limit = line.line
		}
	}
	last := 0
	for n, text := range source {
		line := n + 1
		if line < first || line > limit {
			continue
		}
		for _, output := range outputs {
			parts := strings.Split(output.Path, ".")
			if len(parts) < 3 {
				continue
			}
			needle := parts[len(parts)-2] + "." + output.Name
			if strings.Contains(text, needle) && strings.Contains(text, "=") {
				last = line
			}
		}
	}
	return last
}

func fixedStages(source []string) (uint32, bool) {
	text := strings.Join(source, "\n")
	if strings.Contains(text, "variable-step") || strings.Contains(text, "ode14x") || strings.Contains(text, "ode1be") {
		return 0, false
	}
	match := odeStages.FindStringSubmatch(text)
	if len(match) != 2 || !strings.Contains(text, "rt_ertODEUpdateContinuousStates") {
		return 0, false
	}
	n, err := strconv.ParseUint(match[1], 10, 32)
	if err != nil || n == 0 {
		return 0, false
	}
	if strings.Count(text, "this->step()") < int(n)-1 {
		return 0, false
	}
	return uint32(n), true
}
