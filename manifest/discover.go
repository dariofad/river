package manifest

import (
	"crypto/sha256"
	"debug/dwarf"
	"debug/elf"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

type discoveredModel struct {
	Manifest Model
	Class    *dwarf.StructType
	Funcs    map[string]string
	Data     map[string]RuntimeData
}

type discovery struct {
	BuildID string
	Models  map[string]*discoveredModel
}

func Generate(binary string) (*Manifest, error) {
	absolute, err := filepath.Abs(binary)
	if err != nil {
		return nil, fmt.Errorf("resolve binary path: %w", err)
	}
	binary = absolute
	d, err := inspect(binary)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(d.Models))
	for name := range d.Models {
		names = append(names, name)
	}
	sort.Strings(names)
	m := &Manifest{
		Version:  1,
		Artifact: Artifact{Binary: binary, BuildID: d.BuildID},
		Settings: Settings{SampleEvery: 1},
	}
	for _, name := range names {
		m.Models = append(m.Models, d.Models[name].Manifest)
	}
	return m, nil
}

func inspect(binary string) (*discovery, error) {
	buildID, err := fingerprint(binary)
	if err != nil {
		return nil, err
	}
	ef, err := elf.Open(binary)
	if err != nil {
		return nil, fmt.Errorf("open ELF: %w", err)
	}
	defer ef.Close()
	dw, err := ef.DWARF()
	if err != nil {
		return nil, fmt.Errorf("read DWARF (build the model unstripped with -g): %w", err)
	}
	funcs, err := modelFunctions(ef)
	if err != nil {
		return nil, err
	}
	out := &discovery{BuildID: buildID, Models: make(map[string]*discoveredModel)}
	r := dw.Reader()
	for {
		e, err := r.Next()
		if err != nil {
			return nil, fmt.Errorf("scan DWARF: %w", err)
		}
		if e == nil {
			break
		}
		if e.Tag != dwarf.TagClassType && e.Tag != dwarf.TagStructType {
			continue
		}
		name, _ := e.Val(dwarf.AttrName).(string)
		if name == "" || funcs[name]["step"] == "" {
			continue
		}
		t, err := dw.Type(e.Offset)
		if err != nil {
			continue
		}
		class, ok := unwrapType(t).(*dwarf.StructType)
		if !ok || !looksLikeModel(class) {
			continue
		}
		if _, exists := out.Models[name]; exists {
			continue
		}
		dm := buildModel(name, class, funcs[name])
		out.Models[name] = dm
	}
	if len(out.Models) == 0 {
		return nil, errors.New("no Simulink C++ model class with step(), inputs, or outputs found")
	}
	addStaticData(dw, ef, out)
	return out, nil
}

func buildModel(name string, class *dwarf.StructType, funcs map[string]string) *discoveredModel {
	m := Model{
		Name:    name,
		Enabled: true,
		Hooks: HookRoles{
			Write: "step.entry",
			Read:  "step.return",
		},
	}
	fnNames := make([]string, 0, len(funcs))
	for fn := range funcs {
		fnNames = append(fnNames, fn)
	}
	sort.Strings(fnNames)
	for _, fn := range fnNames {
		for _, phase := range []string{"entry", "return"} {
			h := Hook{ID: fn + "." + phase, Function: fn, Phase: phase}
			m.AvailableHooks = append(m.AvailableHooks, h)
		}
	}
	dm := &discoveredModel{Manifest: m, Class: class, Funcs: funcs, Data: make(map[string]RuntimeData)}
	for _, field := range class.Field {
		switch {
		case strings.HasSuffix(field.Name, "_U"):
			dm.addLeaves(field, "input", true, &dm.Manifest.Inputs)
		case strings.HasSuffix(field.Name, "_Y"):
			dm.addLeaves(field, "output", true, &dm.Manifest.Outputs)
		case strings.HasSuffix(field.Name, "_X"):
			dm.addLeaves(field, "continuous_state", false, &dm.Manifest.States)
		case strings.HasSuffix(field.Name, "_DW"):
			dm.addLeaves(field, "block_state", false, &dm.Manifest.States)
		}
	}
	return dm
}

func (dm *discoveredModel) addLeaves(field *dwarf.StructField, category string, enabled bool, dst *[]Data) {
	prefix := dm.Manifest.Name + "." + field.Name
	var walk func(dwarf.Type, string, int64)
	walk = func(t dwarf.Type, path string, offset int64) {
		t = unwrapType(t)
		if st, ok := t.(*dwarf.StructType); ok {
			for _, child := range st.Field {
				walk(child.Type, path+"."+child.Name, offset+child.ByteOffset)
			}
			return
		}
		primitive, ok := primitiveOf(t)
		leaf := path[strings.LastIndex(path, ".")+1:]
		item := Data{Name: leaf, Path: path, Category: category, Enabled: enabled && ok, Supported: ok}
		if ok {
			item.Type = primitive.Name
			dm.Data[path] = RuntimeData{Path: path, Name: leaf, Category: category, Type: primitive, Base: BaseThis, Offset: offset}
		} else {
			item.Type = t.String()
			item.Reason = "only scalar primitive values are supported"
		}
		*dst = append(*dst, item)
	}
	walk(field.Type, prefix, field.ByteOffset)
}

func (dm *discoveredModel) addStaticLeaves(name string, t dwarf.Type, symbolValue, stepValue uint64) {
	prefix := dm.Manifest.Name + "." + name
	var walk func(dwarf.Type, string, int64)
	walk = func(current dwarf.Type, path string, memberOffset int64) {
		current = unwrapType(current)
		if st, ok := current.(*dwarf.StructType); ok {
			for _, child := range st.Field {
				walk(child.Type, path+"."+child.Name, memberOffset+child.ByteOffset)
			}
			return
		}
		if dm.hasStatePath(path) {
			return
		}
		primitive, ok := primitiveOf(current)
		leaf := path[strings.LastIndex(path, ".")+1:]
		item := Data{Name: leaf, Path: path, Category: "parameter", Supported: ok}
		if ok {
			item.Type = primitive.Name
			delta := int64(symbolValue) - int64(stepValue) + memberOffset
			dm.Data[path] = RuntimeData{Path: path, Name: leaf, Category: "parameter", Type: primitive, Base: BaseELF, Offset: delta}
		} else {
			item.Type = current.String()
			item.Reason = "only scalar primitive values are supported"
		}
		dm.Manifest.States = append(dm.Manifest.States, item)
	}
	walk(t, prefix, 0)
}

// hasStatePath deduplicates every discovered static leaf, including arrays
// and structs that are intentionally absent from dm.Data because they cannot
// be monitored by the current scalar runtime.
func (dm *discoveredModel) hasStatePath(path string) bool {
	for _, state := range dm.Manifest.States {
		if state.Path == path {
			return true
		}
	}
	return false
}

func addStaticData(dw *dwarf.Data, ef *elf.File, found *discovery) {
	syms, err := ef.Symbols()
	if err != nil {
		return
	}
	values := make(map[string]uint64, len(syms))
	for _, symbol := range syms {
		values[symbol.Name] = symbol.Value
	}
	r := dw.Reader()
	for {
		entry, err := r.Next()
		if err != nil || entry == nil {
			return
		}
		if entry.Tag != dwarf.TagVariable {
			continue
		}
		linkage, _ := entry.Val(dwarf.AttrLinkageName).(string)
		parts := decodeNestedName(linkage)
		if len(parts) < 2 {
			continue
		}
		className, variableName := parts[len(parts)-2], parts[len(parts)-1]
		dm := found.Models[className]
		if dm == nil || values[linkage] == 0 {
			continue
		}
		typeOffset, ok := entry.Val(dwarf.AttrType).(dwarf.Offset)
		if !ok {
			continue
		}
		t, err := dw.Type(typeOffset)
		if err != nil {
			continue
		}
		dm.addStaticLeaves(variableName, t, values[linkage], values[dm.Funcs["step"]])
	}
}

func looksLikeModel(t *dwarf.StructType) bool {
	for _, f := range t.Field {
		if strings.HasSuffix(f.Name, "_U") || strings.HasSuffix(f.Name, "_Y") {
			return true
		}
	}
	return false
}

func primitiveOf(t dwarf.Type) (PrimitiveType, bool) {
	t = unwrapType(t)
	switch v := t.(type) {
	case *dwarf.BoolType:
		return PrimitiveType{Name: "bool", Size: uint8(v.ByteSize), Boolean: true}, true
	case *dwarf.FloatType:
		if v.ByteSize == 4 {
			return PrimitiveType{Name: "float32", Size: 4, Floating: true, Signed: true}, true
		}
		if v.ByteSize == 8 {
			return PrimitiveType{Name: "float64", Size: 8, Floating: true, Signed: true}, true
		}
	case *dwarf.IntType:
		return PrimitiveType{Name: "int" + strconv.FormatInt(v.ByteSize*8, 10), Size: uint8(v.ByteSize), Signed: true}, v.ByteSize > 0 && v.ByteSize <= 8
	case *dwarf.UintType:
		return PrimitiveType{Name: "uint" + strconv.FormatInt(v.ByteSize*8, 10), Size: uint8(v.ByteSize)}, v.ByteSize > 0 && v.ByteSize <= 8
	case *dwarf.CharType:
		return PrimitiveType{Name: "int8", Size: 1, Signed: true}, true
	case *dwarf.UcharType:
		return PrimitiveType{Name: "uint8", Size: 1}, true
	}
	return PrimitiveType{}, false
}

func unwrapType(t dwarf.Type) dwarf.Type {
	for {
		switch v := t.(type) {
		case *dwarf.TypedefType:
			t = v.Type
		case *dwarf.QualType:
			t = v.Type
		default:
			return t
		}
	}
}

func modelFunctions(ef *elf.File) (map[string]map[string]string, error) {
	syms, err := ef.Symbols()
	if err != nil {
		return nil, fmt.Errorf("read ELF symbols (binary must not be stripped): %w", err)
	}
	out := make(map[string]map[string]string)
	for _, s := range syms {
		if elf.ST_TYPE(s.Info) != elf.STT_FUNC {
			continue
		}
		parts := decodeNestedName(s.Name)
		if len(parts) < 2 {
			continue
		}
		class, fn := parts[len(parts)-2], parts[len(parts)-1]
		if out[class] == nil {
			out[class] = make(map[string]string)
		}
		if out[class][fn] == "" {
			out[class][fn] = s.Name
		}
	}
	return out, nil
}

func decodeNestedName(name string) []string {
	if !strings.HasPrefix(name, "_ZN") {
		return nil
	}
	s := name[3:]
	var parts []string
	for len(s) > 0 && s[0] != 'E' {
		i := 0
		for i < len(s) && s[i] >= '0' && s[i] <= '9' {
			i++
		}
		if i == 0 {
			return parts
		}
		n, err := strconv.Atoi(s[:i])
		if err != nil || n <= 0 || i+n > len(s) {
			return parts
		}
		parts = append(parts, s[i:i+n])
		s = s[i+n:]
	}
	return parts
}

func fingerprint(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open binary: %w", err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("fingerprint binary: %w", err)
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}
