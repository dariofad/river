package manifest

import (
	"errors"
	"fmt"
)

func Compile(m *Manifest) (*RuntimePlan, error) {
	if m.Version != 1 {
		return nil, fmt.Errorf("unsupported manifest version %d", m.Version)
	}
	if m.Artifact.Binary == "" {
		return nil, errors.New("manifest artifact.binary is required")
	}
	if m.Settings.SampleEvery == 0 {
		return nil, errors.New("settings.sample_every must be at least 1")
	}
	d, err := inspect(m.Artifact.Binary)
	if err != nil {
		return nil, err
	}
	if m.Artifact.BuildID == "" || m.Artifact.BuildID != d.BuildID {
		return nil, fmt.Errorf("manifest build_id does not match %s; regenerate the manifest", m.Artifact.Binary)
	}
	plan := &RuntimePlan{Binary: m.Artifact.Binary, BuildID: d.BuildID, Cycles: m.Settings.Cycles, SampleEvery: m.Settings.SampleEvery, StateByName: make(map[string]RuntimeData)}
	var nextDataID uint32
	for _, configured := range m.Models {
		if !configured.Selected {
			continue
		}
		dm := d.Models[configured.Name]
		if dm == nil {
			return nil, fmt.Errorf("model %q is not present in the current ELF", configured.Name)
		}
		rm := RuntimeModel{ID: uint32(len(plan.Models)), Name: configured.Name, StepSymbol: dm.Funcs["step"]}
		if rm.InputWriteHook, err = compileHook(configured, dm, configured.Hooks.InputWrite, "input_write"); err != nil {
			return nil, err
		}
		if rm.StateWriteHook, err = compileHook(configured, dm, configured.Hooks.StateWrite, "state_write"); err != nil {
			return nil, err
		}
		if rm.SampleHook, err = compileHook(configured, dm, configured.Hooks.Sample, "sample"); err != nil {
			return nil, err
		}
		compileData := func(items []Data, dst *[]RuntimeData) error {
			for _, item := range items {
				if !item.Selected {
					continue
				}
				if !item.Supported {
					return fmt.Errorf("%s selects unsupported data %q: %s", configured.Name, item.Path, item.Reason)
				}
				rd, ok := dm.Data[item.Path]
				if !ok {
					return fmt.Errorf("data path %q is stale or was edited; regenerate the manifest", item.Path)
				}
				if rd.Type.Name != item.Type {
					return fmt.Errorf("type for %q changed from %q to %q; regenerate the manifest", item.Path, item.Type, rd.Type.Name)
				}
				rd.ID, rd.ModelID = nextDataID, rm.ID
				rd.GraphicalName = item.GraphicalName
				nextDataID++
				*dst = append(*dst, rd)
			}
			return nil
		}
		if err := compileData(configured.Inputs, &rm.Inputs); err != nil {
			return nil, err
		}
		if err := compileData(configured.Outputs, &rm.Outputs); err != nil {
			return nil, err
		}
		if err := compileData(configured.States, &rm.States); err != nil {
			return nil, err
		}
		for _, state := range rm.States {
			plan.StateByName[state.Path] = state
			qualified := rm.Name + "." + state.Name
			if _, exists := plan.StateByName[qualified]; !exists {
				plan.StateByName[qualified] = state
			}
		}
		plan.Models = append(plan.Models, rm)
	}
	if len(plan.Models) == 0 {
		return nil, errors.New("manifest does not select any models")
	}
	return plan, nil
}

func compileHook(configured Model, dm *discoveredModel, id, role string) (RuntimeHook, error) {
	for _, h := range dm.Manifest.PossibleHooks {
		if h.ID != id {
			continue
		}
		allowed := false
		for _, candidate := range h.AllowedRoles {
			if candidate == role {
				allowed = true
				break
			}
		}
		if !allowed {
			return RuntimeHook{}, fmt.Errorf("hook %q is not valid for role %q", id, role)
		}
		symbol := dm.Funcs[h.Function]
		if symbol == "" {
			return RuntimeHook{}, fmt.Errorf("hook function %q is missing from model %q", h.Function, configured.Name)
		}
		return RuntimeHook{ID: id, Symbol: symbol, Function: h.Function, Phase: h.Phase}, nil
	}
	return RuntimeHook{}, fmt.Errorf("unknown hook %q for model %q", id, configured.Name)
}
