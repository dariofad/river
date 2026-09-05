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

	"golang.org/x/arch/arm64/arm64asm"
	"golang.org/x/arch/x86/x86asm"
)

type discoveredModel struct {
	Manifest          Model
	Class             *dwarf.StructType
	Funcs             map[string]string
	Data              map[string]RuntimeData
	InstanceAddresses []uint64
}

type discovery struct {
	BuildID string
	Models  map[string]*discoveredModel
}

// Generate returns a manifest together with diagnostics for
// conservative defaults that require user review.
func Generate(binary string) (*Manifest, []string, error) {
	absolute, err := filepath.Abs(binary)
	if err != nil {
		return nil, nil, fmt.Errorf("resolve binary path: %w", err)
	}
	binary = absolute
	d, err := inspect(binary)
	if err != nil {
		return nil, nil, err
	}
	names := make([]string, 0, len(d.Models))
	for name := range d.Models {
		names = append(names, name)
	}
	sort.Strings(names)
	m := &Manifest{
		Version:  1,
		Artifact: Artifact{Binary: binary, BuildID: d.BuildID},
		Settings: Settings{SampleEvery: 1, TimerModel: names[0]},
	}
	for _, name := range names {
		model := d.Models[name].Manifest
		// The simulator JSON payload has one global signal namespace. Leave
		// additional discovered models available for the user to configure, but
		// disabled by default so equal input names cannot make a fresh manifest
		// uncompilable.
		model.Enabled = name == m.Settings.TimerModel
		m.Models = append(m.Models, model)
	}
	warnings := inferSemanticDefaults(binary, m, d)
	return m, warnings, nil
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
	if err := addModelInstances(dw, ef, out); err != nil {
		return nil, err
	}
	addStaticData(dw, ef, out)
	return out, nil
}

func buildModel(name string, class *dwarf.StructType, funcs map[string]string) *discoveredModel {
	m := Model{
		Name:    name,
		Enabled: true,
	}
	fnNames := make([]string, 0, len(funcs))
	for fn := range funcs {
		fnNames = append(fnNames, fn)
	}
	sort.Strings(fnNames)
	for _, fn := range fnNames {
		m.AvailableHooks = append(m.AvailableHooks, Hook{ID: fn})
	}
	dm := &discoveredModel{Manifest: m, Class: class, Funcs: funcs, Data: make(map[string]RuntimeData)}
	for _, field := range class.Field {
		switch {
		case strings.HasSuffix(field.Name, "_U"):
			dm.addLeaves(field, "input", &dm.Manifest.Inputs)
		case strings.HasSuffix(field.Name, "_Y"):
			dm.addLeaves(field, "output", &dm.Manifest.Outputs)
		case strings.HasSuffix(field.Name, "_X"):
			dm.addLeaves(field, "continuous_state", &dm.Manifest.States)
		case strings.HasSuffix(field.Name, "_DW"):
			dm.addLeaves(field, "block_state", &dm.Manifest.States)
		}
	}
	inputs := supportedPaths(dm.Manifest.Inputs)
	if len(inputs) > 0 {
		dm.Manifest.Hooks = append(dm.Manifest.Hooks, HookSelection{ID: "step", Phase: "entry", Action: "write", Data: inputs})
	}
	reads := append(inputs, supportedPaths(dm.Manifest.Outputs)...)
	if len(reads) > 0 {
		dm.Manifest.Hooks = append(dm.Manifest.Hooks, HookSelection{ID: "step", Phase: "return", Action: "read", Data: reads})
	}
	return dm
}

func addModelInstances(dw *dwarf.Data, ef *elf.File, found *discovery) error {
	objectAddresses, err := objectSymbolAddresses(ef)
	if err != nil {
		return err
	}
	r := dw.Reader()
	for {
		entry, err := r.Next()
		if err != nil {
			return fmt.Errorf("scan DWARF model instances: %w", err)
		}
		if entry == nil {
			break
		}
		if entry.Tag != dwarf.TagVariable {
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
		st, ok := unwrapType(t).(*dwarf.StructType)
		if !ok {
			continue
		}
		dm := found.Models[st.StructName]
		if dm == nil {
			continue
		}
		linkage, _ := entry.Val(dwarf.AttrLinkageName).(string)
		name, _ := entry.Val(dwarf.AttrName).(string)
		address, ok := objectAddresses[linkage]
		if !ok && name != "" {
			address, ok = objectAddresses[name]
		}
		if !ok {
			address, ok = dwarfAddress(entry.Val(dwarf.AttrLocation), ef)
		}
		// An ELF virtual address of zero cannot identify a model instance in a
		// loadable executable. Treat it as an unavailable DWARF location rather
		// than emitting member offsets as simulator addresses.
		if !ok || address == 0 || containsAddress(dm.InstanceAddresses, address) {
			continue
		}
		dm.InstanceAddresses = append(dm.InstanceAddresses, address)
	}
	for _, dm := range found.Models {
		sort.Slice(dm.InstanceAddresses, func(i, j int) bool {
			return dm.InstanceAddresses[i] < dm.InstanceAddresses[j]
		})
	}
	return nil
}

func objectSymbolAddresses(ef *elf.File) (map[string]uint64, error) {
	syms, err := ef.Symbols()
	if err != nil {
		return nil, fmt.Errorf("read ELF symbols: %w", err)
	}
	addresses := make(map[string]uint64, len(syms))
	for _, symbol := range syms {
		if elf.ST_TYPE(symbol.Info) == elf.STT_OBJECT && symbol.Name != "" && symbol.Value != 0 {
			addresses[symbol.Name] = symbol.Value
		}
	}
	return addresses, nil
}

func dwarfAddress(raw any, ef *elf.File) (uint64, bool) {
	expr, ok := raw.([]byte)
	if !ok || len(expr) < 2 || expr[0] != 0x03 { // DW_OP_addr
		return 0, false
	}
	switch ef.Class {
	case elf.ELFCLASS64:
		if len(expr) < 9 {
			return 0, false
		}
		return ef.ByteOrder.Uint64(expr[1:9]), true
	case elf.ELFCLASS32:
		if len(expr) < 5 {
			return 0, false
		}
		return uint64(ef.ByteOrder.Uint32(expr[1:5])), true
	default:
		return 0, false
	}
}

func containsAddress(addresses []uint64, target uint64) bool {
	for _, address := range addresses {
		if address == target {
			return true
		}
	}
	return false
}

func functionInstructions(ef *elf.File, symbolName string) (map[uint64]bool, []uint64, error) {
	symbol, err := findFunctionSymbol(ef, symbolName)
	if err != nil {
		return nil, nil, err
	}
	if symbol.Size == 0 {
		return nil, nil, fmt.Errorf("function symbol %q has no size", symbolName)
	}
	if int(symbol.Section) >= len(ef.Sections) {
		return nil, nil, fmt.Errorf("function symbol %q has an invalid section", symbolName)
	}
	section := ef.Sections[symbol.Section]
	data, err := section.Data()
	if err != nil {
		return nil, nil, fmt.Errorf("read function %q: %w", symbolName, err)
	}
	start := symbol.Value - section.Addr
	if start > uint64(len(data)) || symbol.Size > uint64(len(data))-start {
		return nil, nil, fmt.Errorf("function symbol %q lies outside its section", symbolName)
	}
	code := data[start : start+symbol.Size]
	boundaries := make(map[uint64]bool)
	var returns []uint64
	for offset := uint64(0); offset < uint64(len(code)); {
		boundaries[offset] = true
		length, isReturn, err := decodeInstruction(ef.Machine, code[offset:])
		if err != nil {
			return nil, nil, fmt.Errorf("decode %q at offset %d: %w", symbolName, offset, err)
		}
		if isReturn {
			returns = append(returns, offset)
		}
		offset += uint64(length)
	}
	return boundaries, returns, nil
}

func decodeInstruction(machine elf.Machine, code []byte) (int, bool, error) {
	switch machine {
	case elf.EM_X86_64:
		// x86asm v0.20 predates Intel CET's ENDBR64 instruction and decodes
		// its REP prefix separately. Generated model binaries commonly start
		// every function with this four-byte sequence.
		if len(code) >= 4 && code[0] == 0xf3 && code[1] == 0x0f && code[2] == 0x1e && code[3] == 0xfa {
			return 4, false, nil
		}
		inst, err := x86asm.Decode(code, 64)
		if err != nil {
			return 0, false, err
		}
		return inst.Len, inst.Op == x86asm.RET || inst.Op == x86asm.LRET, nil
	case elf.EM_AARCH64:
		if len(code) < 4 {
			return 0, false, io.ErrUnexpectedEOF
		}
		inst, err := arm64asm.Decode(code[:4])
		if err != nil {
			return 0, false, err
		}
		return 4, inst.Op == arm64asm.RET, nil
	default:
		return 0, false, fmt.Errorf("unsupported ELF machine %s", machine)
	}
}

func findFunctionSymbol(ef *elf.File, name string) (elf.Symbol, error) {
	symbols, err := ef.Symbols()
	if err != nil {
		return elf.Symbol{}, fmt.Errorf("read ELF symbols: %w", err)
	}
	for _, symbol := range symbols {
		if symbol.Name == name && elf.ST_TYPE(symbol.Info) == elf.STT_FUNC {
			return symbol, nil
		}
	}
	return elf.Symbol{}, fmt.Errorf("function symbol %q is missing", name)
}

func (dm *discoveredModel) addLeaves(field *dwarf.StructField, category string, dst *[]Data) {
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
		primitive, ok, reason := simulatorPrimitiveOf(t)
		leaf := path[strings.LastIndex(path, ".")+1:]
		item := Data{Name: leaf, Path: path, Category: category, Supported: ok}
		if primitive.Name != "" {
			item.Type = primitive.Name
		} else {
			item.Type = t.String()
		}
		if ok {
			dm.Data[path] = RuntimeData{Path: path, Name: leaf, Category: category, Type: primitive, Base: BaseThis, Offset: offset}
		} else {
			item.Reason = reason
		}
		*dst = append(*dst, item)
	}
	walk(field.Type, prefix, field.ByteOffset)
}

func supportedPaths(items []Data) []string {
	paths := make([]string, 0, len(items))
	for _, item := range items {
		if item.Supported {
			paths = append(paths, item.Path)
		}
	}
	return paths
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
		primitive, ok, reason := simulatorPrimitiveOf(current)
		leaf := path[strings.LastIndex(path, ".")+1:]
		item := Data{Name: leaf, Path: path, Category: "parameter", Supported: ok}
		if primitive.Name != "" {
			item.Type = primitive.Name
		} else {
			item.Type = current.String()
		}
		if ok {
			delta := int64(symbolValue) - int64(stepValue) + memberOffset
			dm.Data[path] = RuntimeData{Path: path, Name: leaf, Category: "parameter", Type: primitive, Base: BaseELF, Offset: delta}
		} else {
			item.Reason = reason
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

func simulatorPrimitiveOf(t dwarf.Type) (PrimitiveType, bool, string) {
	primitive, ok := primitiveOf(t)
	if !ok {
		return PrimitiveType{}, false, "only scalar primitive values are supported"
	}
	if primitive.Name != "float64" {
		return primitive, false, "the simulator supports only scalar float64 values"
	}
	return primitive, true, ""
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
