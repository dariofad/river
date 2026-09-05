package manifest

import (
	"debug/dwarf"
	"debug/elf"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/dariofad/river/my_types"
)

const simulatorSignalLimit = 16

// CompileConfiguration validates a user-edited manifest against binary and lowers it
// to the configuration consumed by the unchanged simulator.
func CompileConfiguration(m *Manifest, binary string) (*my_types.Configuration, error) {
	absolute, err := filepath.Abs(binary)
	if err != nil {
		return nil, fmt.Errorf("resolve binary path: %w", err)
	}
	d, err := inspect(absolute)
	if err != nil {
		return nil, err
	}
	if m.Version != 1 {
		return nil, fmt.Errorf("unsupported manifest version %d", m.Version)
	}
	if m.Artifact.BuildID == "" || m.Artifact.BuildID != d.BuildID {
		return nil, fmt.Errorf("manifest build_id does not match %s; regenerate the manifest", absolute)
	}
	ef, err := elf.Open(absolute)
	if err != nil {
		return nil, fmt.Errorf("open ELF: %w", err)
	}
	defer ef.Close()
	dw, err := ef.DWARF()
	if err != nil {
		return nil, fmt.Errorf("read DWARF (build the model unstripped with -g): %w", err)
	}

	config := &my_types.Configuration{ModelPath: absolute, MinorToMajorRatio: strconv.FormatUint(uint64(m.Settings.SampleEvery), 10), NofCycles: strconv.FormatUint(uint64(m.Settings.Cycles), 10), Reads: []my_types.Group{}, Writes: []my_types.Group{}}
	var problems []string
	if m.Settings.Cycles == 0 {
		problems = append(problems, "settings.cycles must be at least 1")
	}
	if m.Settings.SampleEvery == 0 {
		problems = append(problems, "settings.sample_every must be at least 1")
	}

	enabledModels := make(map[string]bool)
	readNames, writeNames := make(map[string]string), make(map[string]string)
	readCount, writeCount := 0, 0
	for _, configured := range m.Models {
		if !configured.Enabled {
			continue
		}
		if enabledModels[configured.Name] {
			problems = append(problems, fmt.Sprintf("model %q appears more than once", configured.Name))
			continue
		}
		enabledModels[configured.Name] = true
		dm := d.Models[configured.Name]
		if dm == nil {
			problems = append(problems, fmt.Sprintf("model %q is not present in the target ELF", configured.Name))
			continue
		}
		step, err := findFunctionSymbol(ef, dm.Funcs["step"])
		if err != nil {
			problems = append(problems, fmt.Sprintf("model %q: %v", configured.Name, err))
			continue
		}

		instanceAddress, addressOK := uint64(0), len(dm.InstanceAddresses) == 1
		if !addressOK {
			problems = append(problems, fmt.Sprintf("model %q must have exactly one statically addressable instance; found %d", configured.Name, len(dm.InstanceAddresses)))
		} else {
			instanceAddress = dm.InstanceAddresses[0]
		}
		catalog := buildDataCatalog(configured, &problems)
		hooks := buildHookCatalog(configured, &problems)
		seenSelections := make(map[string]bool)
		for _, selected := range configured.Hooks {
			key := selected.ID + "\x00" + selected.Phase + "\x00" + selected.Action
			if selected.Phase == "custom" && selected.Offset != nil {
				key += "\x00" + strconv.FormatUint(*selected.Offset, 10)
			}
			if seenSelections[key] {
				problems = append(problems, fmt.Sprintf("model %q selects hook %q at %s for %s more than once", configured.Name, selected.ID, selected.Phase, selected.Action))
				continue
			}
			seenSelections[key] = true
			if selected.Action != "read" && selected.Action != "write" {
				problems = append(problems, fmt.Sprintf("model %q hook %q has invalid action %q", configured.Name, selected.ID, selected.Action))
				continue
			}
			hook := hooks[selected.ID]
			if hook == nil {
				problems = append(problems, fmt.Sprintf("model %q %s hook: unknown hook %q", configured.Name, selected.Action, selected.ID))
				continue
			}
			symbol, offset, err := compileHook(ef, dw, dm, hook.ID, selected.Phase, selected.Offset, dm.Manifest.Outputs)
			if err != nil {
				problems = append(problems, fmt.Sprintf("model %q %s hook %q at %s: %v", configured.Name, selected.Action, selected.ID, selected.Phase, err))
				continue
			}
			if len(selected.Data) == 0 {
				problems = append(problems, fmt.Sprintf("model %q %s hook %q has no data", configured.Name, selected.Action, selected.ID))
				continue
			}
			signals := compileSelection(ef, selected, catalog, dm, instanceAddress, addressOK, step.Value, &problems)
			for _, signal := range signals {
				if selected.Action == "read" {
					checkDuplicateName(readNames, signal.Name, configured.Name, "read", &problems)
					readCount++
				} else {
					checkDuplicateName(writeNames, signal.Name, configured.Name, "write", &problems)
					writeCount++
				}
			}
			if len(signals) == 0 {
				continue
			}
			group := my_types.Group{Symbol: symbol, Offset: strconv.FormatUint(offset, 10), Signals: signals}
			if selected.Action == "read" {
				config.Reads = append(config.Reads, group)
			} else {
				config.Writes = append(config.Writes, group)
			}
		}
	}

	if len(enabledModels) == 0 {
		problems = append(problems, "manifest does not enable any models")
	}
	timerModel := d.Models[m.Settings.TimerModel]
	switch {
	case m.Settings.TimerModel == "":
		problems = append(problems, "settings.timer_model is required")
	case !enabledModels[m.Settings.TimerModel]:
		problems = append(problems, fmt.Sprintf("timer model %q is not enabled", m.Settings.TimerModel))
	case timerModel == nil:
		problems = append(problems, fmt.Sprintf("timer model %q is not present in the target ELF", m.Settings.TimerModel))
	default:
		config.TimerSymbol = timerModel.Funcs["step"]
	}
	if readCount > simulatorSignalLimit {
		problems = append(problems, fmt.Sprintf("configuration has %d read signals; the simulator supports at most %d", readCount, simulatorSignalLimit))
	}
	if writeCount > simulatorSignalLimit {
		problems = append(problems, fmt.Sprintf("configuration has %d write signals; the simulator supports at most %d", writeCount, simulatorSignalLimit))
	}
	if len(problems) > 0 {
		return nil, errors.New("manifest cannot be compiled:\n  - " + strings.Join(problems, "\n  - "))
	}
	return config, nil
}

func buildDataCatalog(model Model, problems *[]string) map[string]Data {
	catalog := make(map[string]Data, len(model.Inputs)+len(model.Outputs)+len(model.States))
	for _, items := range [][]Data{model.Inputs, model.Outputs, model.States} {
		for _, item := range items {
			if item.Path == "" {
				*problems = append(*problems, fmt.Sprintf("model %q contains data with an empty path", model.Name))
				continue
			}
			if _, exists := catalog[item.Path]; exists {
				*problems = append(*problems, fmt.Sprintf("model %q declares data path %q more than once", model.Name, item.Path))
				continue
			}
			catalog[item.Path] = item
		}
	}
	return catalog
}

func buildHookCatalog(model Model, problems *[]string) map[string]*Hook {
	catalog := make(map[string]*Hook, len(model.AvailableHooks))
	for i := range model.AvailableHooks {
		hook := &model.AvailableHooks[i]
		if hook.ID == "" {
			*problems = append(*problems, fmt.Sprintf("model %q has an available hook with an empty id", model.Name))
			continue
		}
		if _, exists := catalog[hook.ID]; exists {
			*problems = append(*problems, fmt.Sprintf("model %q declares available hook %q more than once", model.Name, hook.ID))
			continue
		}
		catalog[hook.ID] = hook
	}
	return catalog
}

func compileHook(ef *elf.File, dw *dwarf.Data, dm *discoveredModel, function, phase string, customOffset *uint64, outputs []Data) (string, uint64, error) {
	if function == "" {
		return "", 0, errors.New("function is required")
	}
	if phase == "" {
		return "", 0, errors.New("phase is required")
	}
	symbol := dm.Funcs[function]
	if symbol == "" {
		return "", 0, fmt.Errorf("function %q is missing from the target ELF", function)
	}
	boundaries, returns, err := functionInstructions(ef, symbol)
	if err != nil {
		return "", 0, err
	}
	switch phase {
	case "entry":
		if customOffset != nil {
			return "", 0, errors.New("offset is only valid for the custom phase")
		}
		return symbol, 0, nil
	case "return":
		if customOffset != nil {
			return "", 0, errors.New("offset is only valid for the custom phase")
		}
		if len(returns) == 0 {
			return "", 0, fmt.Errorf("function %q has no return instruction", function)
		}
		return symbol, returns[len(returns)-1], nil
	case "post_outputs":
		if customOffset != nil {
			return "", 0, errors.New("offset is only valid for the custom phase")
		}
		if function != "step" {
			return "", 0, fmt.Errorf("post_outputs is only available for step")
		}
		functionSymbol, err := findFunctionSymbol(ef, symbol)
		if err != nil {
			return "", 0, err
		}
		source, lines, err := functionSource(dw, functionSymbol, outputs)
		if err != nil {
			return "", 0, fmt.Errorf("locate post-output source site: %w", err)
		}
		offset, ok := postOutputOffset(source, lines, functionSymbol, outputs)
		if !ok || !boundaries[offset] {
			return "", 0, errors.New("cannot resolve a post-output instruction boundary")
		}
		return symbol, offset, nil
	case "custom":
		if customOffset == nil {
			return "", 0, errors.New("custom phase requires an offset")
		}
		if !boundaries[*customOffset] {
			return "", 0, fmt.Errorf("offset %d is not an instruction boundary within %s", *customOffset, symbol)
		}
		return symbol, *customOffset, nil
	default:
		return "", 0, fmt.Errorf("unknown hook phase %q", phase)
	}
}

func compileSelection(ef *elf.File, selected HookSelection, catalog map[string]Data, dm *discoveredModel, instanceAddress uint64, addressOK bool, stepAddress uint64, problems *[]string) []my_types.Signal {
	seenPaths := make(map[string]bool, len(selected.Data))
	signals := make([]my_types.Signal, 0, len(selected.Data))
	for _, path := range selected.Data {
		if seenPaths[path] {
			*problems = append(*problems, fmt.Sprintf("%s hook %q lists data path %q more than once", selected.Action, selected.ID, path))
			continue
		}
		seenPaths[path] = true
		item, exists := catalog[path]
		if !exists {
			*problems = append(*problems, fmt.Sprintf("%s hook %q references unknown data path %q", selected.Action, selected.ID, path))
			continue
		}
		if !item.Supported {
			*problems = append(*problems, fmt.Sprintf("data %q is unsupported: %s", item.Path, item.Reason))
			continue
		}
		discovered, ok := dm.Data[item.Path]
		if !ok {
			*problems = append(*problems, fmt.Sprintf("data path %q is stale or was edited", item.Path))
			continue
		}
		if discovered.Type.Name != item.Type {
			*problems = append(*problems, fmt.Sprintf("type for %q changed from %q to %q", item.Path, item.Type, discovered.Type.Name))
			continue
		}
		if item.Type != "float64" {
			*problems = append(*problems, fmt.Sprintf("data %q has type %q; the simulator supports only float64", item.Path, item.Type))
			continue
		}
		if item.Name == "" {
			*problems = append(*problems, fmt.Sprintf("data %q has an empty name", item.Path))
			continue
		}
		address, ok := configurationAddress(discovered, instanceAddress, addressOK, stepAddress)
		if !ok {
			*problems = append(*problems, fmt.Sprintf("cannot resolve address for %q", item.Path))
			continue
		}
		if err := validateDataRange(ef, address, 8, selected.Action == "write"); err != nil {
			*problems = append(*problems, fmt.Sprintf("data %q: %v", item.Path, err))
			continue
		}
		signals = append(signals, my_types.Signal{Name: item.Name, Type: item.Type, Addr: strconv.FormatUint(address, 16)})
	}
	return signals
}

func validateDataRange(ef *elf.File, address, size uint64, writable bool) error {
	if size == 0 || address > ^uint64(0)-(size-1) {
		return fmt.Errorf("address range %#x+%d overflows", address, size)
	}
	last := address + size - 1
	for _, program := range ef.Progs {
		if program.Type != elf.PT_LOAD || program.Memsz > ^uint64(0)-program.Vaddr {
			continue
		}
		end := program.Vaddr + program.Memsz
		if address < program.Vaddr || last >= end {
			continue
		}
		if writable && program.Flags&elf.PF_W == 0 {
			return fmt.Errorf("write address %#x is not in a writable load segment", address)
		}
		return nil
	}
	return fmt.Errorf("address %#x is outside the target's loadable image", address)
}

func configurationAddress(data RuntimeData, instanceAddress uint64, instanceOK bool, stepAddress uint64) (uint64, bool) {
	switch data.Base {
	case BaseThis:
		if !instanceOK {
			return 0, false
		}
		return addSignedOffset(instanceAddress, data.Offset)
	case BaseELF:
		return addSignedOffset(stepAddress, data.Offset)
	default:
		return 0, false
	}
}

func addSignedOffset(base uint64, offset int64) (uint64, bool) {
	if offset >= 0 {
		delta := uint64(offset)
		return base + delta, base <= ^uint64(0)-delta
	}
	delta := uint64(-(offset + 1)) + 1
	return base - delta, base >= delta
}

func checkDuplicateName(seen map[string]string, name, model, direction string, problems *[]string) {
	if previous, ok := seen[name]; ok {
		*problems = append(*problems, fmt.Sprintf("duplicate %s signal name %q in models %q and %q", direction, name, previous, model))
		return
	}
	seen[name] = model
}
