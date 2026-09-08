package simulator

import (
	"debug/elf"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/dariofad/river/my_types"
)

type elfLoadSegment struct {
	start  uint64
	end    uint64
	offset uint64
	flags  elf.ProgFlag
}

type elfImage struct {
	loads   []elfLoadSegment
	symbols map[string]uint64
}

type relocationConfig struct {
	image           *elfImage
	targetPath      string
	signalAddresses []uint64
}

const maxSignalsPerDirection = 16

func uprobeCookie(groupBase, groupSize int) uint64 {
	return uint64(groupBase<<4 | (groupSize - 1))
}

func validateSignalGroups(kind string, groups []my_types.Group) error {
	total := 0
	for _, group := range groups {
		groupSize := len(group.Signals)
		if groupSize == 0 {
			return fmt.Errorf("%s group %q contains no signals", kind, group.Symbol)
		}
		if groupSize > maxSignalsPerDirection {
			return fmt.Errorf("%s group %q contains %d signals; at most %d are supported", kind, group.Symbol, groupSize, maxSignalsPerDirection)
		}
		total += groupSize
		if total > maxSignalsPerDirection {
			return fmt.Errorf("configuration contains %d %s signals; at most %d are supported", total, kind, maxSignalsPerDirection)
		}
	}
	return nil
}

func configureRelocation(config my_types.Configuration) (*relocationConfig, error) {
	if err := validateSignalGroups("read", config.Reads); err != nil {
		return nil, err
	}
	if err := validateSignalGroups("write", config.Writes); err != nil {
		return nil, err
	}

	image, err := inspectELF(config.ModelPath)
	if err != nil {
		return nil, err
	}

	targetPath, err := filepath.EvalSymlinks(config.ModelPath)
	if err != nil {
		return nil, fmt.Errorf("resolve target ELF path %q: %w", config.ModelPath, err)
	}
	relocation := &relocationConfig{image: image, targetPath: targetPath}
	for _, item := range []struct {
		kind     string
		groups   []my_types.Group
		writable bool
	}{
		{kind: "read", groups: config.Reads},
		{kind: "write", groups: config.Writes, writable: true},
	} {
		for _, group := range item.groups {
			offset, parseErr := strconv.ParseUint(group.Offset, 0, 64)
			if parseErr != nil {
				return nil, fmt.Errorf("parse %s hook offset %q: %w", item.kind, group.Offset, parseErr)
			}
			if group.Retprobe && offset != 0 {
				return nil, fmt.Errorf("%s retprobe hook %q must use offset 0", item.kind, group.Symbol)
			}
			_, hookErr := image.hookAddress(group.Symbol, offset)
			if hookErr != nil {
				return nil, fmt.Errorf("resolve %s hook %q: %w", item.kind, group.Symbol, hookErr)
			}
			for _, signal := range group.Signals {
				typeInfo, typeErr := my_types.ParseSignalType(signal.Type)
				if typeErr != nil {
					return nil, fmt.Errorf("invalid type for %s signal %q: %w", item.kind, signal.Name, typeErr)
				}
				address, parseErr := strconv.ParseUint(signal.Addr, 0, 64)
				if parseErr != nil {
					return nil, fmt.Errorf("parse ELF address %q for %s signal %q: %w", signal.Addr, item.kind, signal.Name, parseErr)
				}
				if err := image.validateDataRange(address, uint64(typeInfo.Size), item.writable); err != nil {
					return nil, fmt.Errorf("invalid address for %s signal %q: %w", item.kind, signal.Name, err)
				}
				relocation.signalAddresses = append(relocation.signalAddresses, address)
			}
		}
	}
	return relocation, nil
}

func inspectELF(path string) (*elfImage, error) {
	f, err := elf.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open target ELF %q: %w", path, err)
	}
	defer f.Close()

	image := &elfImage{symbols: make(map[string]uint64)}
	for _, prog := range f.Progs {
		if prog.Type != elf.PT_LOAD {
			continue
		}
		end, ok := addUint64(prog.Vaddr, prog.Memsz)
		if !ok {
			return nil, fmt.Errorf("target ELF %q contains an overflowing PT_LOAD segment", path)
		}
		image.loads = append(image.loads, elfLoadSegment{start: prog.Vaddr, end: end, offset: prog.Off, flags: prog.Flags})
	}
	if len(image.loads) == 0 {
		return nil, fmt.Errorf("target ELF %q has no loadable segments", path)
	}

	addSymbols := func(symbols []elf.Symbol) {
		for _, symbol := range symbols {
			if symbol.Name != "" && symbol.Value != 0 {
				if _, exists := image.symbols[symbol.Name]; !exists {
					image.symbols[symbol.Name] = symbol.Value
				}
			}
		}
	}
	if symbols, symbolErr := f.Symbols(); symbolErr == nil {
		addSymbols(symbols)
	}
	if symbols, symbolErr := f.DynamicSymbols(); symbolErr == nil {
		addSymbols(symbols)
	}

	return image, nil
}

type processMapping struct {
	start  uint64
	offset uint64
	path   string
}

func (relocation *relocationConfig) runtimeAddresses(pid int) ([]uint64, uint64, error) {
	maps, err := os.ReadFile(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return nil, 0, fmt.Errorf("read target process mappings: %w", err)
	}
	bias, err := relocation.image.loadBias(parseProcessMappings(string(maps)), relocation.targetPath, os.Getpagesize())
	if err != nil {
		return nil, 0, err
	}
	runtimeAddresses := make([]uint64, len(relocation.signalAddresses))
	for i, address := range relocation.signalAddresses {
		runtimeAddress, ok := addUint64(address, bias)
		if !ok {
			return nil, 0, fmt.Errorf("runtime address for signal %d overflows", i)
		}
		runtimeAddresses[i] = runtimeAddress
	}
	return runtimeAddresses, bias, nil
}

func parseProcessMappings(contents string) []processMapping {
	var mappings []processMapping
	for _, line := range strings.Split(contents, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		addressRange := strings.SplitN(fields[0], "-", 2)
		if len(addressRange) != 2 {
			continue
		}
		start, startErr := strconv.ParseUint(addressRange[0], 16, 64)
		offset, offsetErr := strconv.ParseUint(fields[2], 16, 64)
		if startErr != nil || offsetErr != nil {
			continue
		}
		mappings = append(mappings, processMapping{start: start, offset: offset, path: strings.TrimSuffix(fields[5], " (deleted)")})
	}
	return mappings
}

func (image *elfImage) loadBias(mappings []processMapping, targetPath string, pageSize int) (uint64, error) {
	if pageSize <= 0 {
		return 0, fmt.Errorf("invalid page size %d", pageSize)
	}
	page := uint64(pageSize)
	for _, mapping := range mappings {
		mappedPath, err := filepath.EvalSymlinks(mapping.path)
		if err != nil || mappedPath != targetPath {
			continue
		}
		for _, load := range image.loads {
			if mapping.offset != alignDown(load.offset, page) {
				continue
			}
			segmentStart := alignDown(load.start, page)
			if mapping.start < segmentStart {
				continue
			}
			return mapping.start - segmentStart, nil
		}
	}
	return 0, fmt.Errorf("cannot find a load mapping for target ELF %q", targetPath)
}

func alignDown(value, alignment uint64) uint64 {
	return value &^ (alignment - 1)
}

func addUint64(a, b uint64) (uint64, bool) {
	if b > math.MaxUint64-a {
		return 0, false
	}
	return a + b, true
}

func (image *elfImage) hookAddress(symbol string, offset uint64) (uint64, error) {
	address, ok := image.symbols[symbol]
	if !ok {
		return 0, fmt.Errorf("hook symbol %q is not present in the target ELF", symbol)
	}
	address, ok = addUint64(address, offset)
	if !ok {
		return 0, fmt.Errorf("hook symbol %q plus offset %d overflows an ELF address", symbol, offset)
	}
	if err := image.validateAddress(address, false, true); err != nil {
		return 0, fmt.Errorf("hook %q plus offset %d: %w", symbol, offset, err)
	}
	return address, nil
}

func (image *elfImage) validateDataAddress(address uint64, writable bool) error {
	return image.validateDataRange(address, 1, writable)
}

func (image *elfImage) validateDataRange(address, size uint64, writable bool) error {
	if size == 0 {
		return fmt.Errorf("ELF address %#x has a zero-sized access", address)
	}
	last, ok := addUint64(address, size-1)
	if !ok {
		return fmt.Errorf("ELF address range %#x+%d overflows", address, size)
	}
	for _, load := range image.loads {
		if address < load.start || last >= load.end {
			continue
		}
		if writable && load.flags&elf.PF_W == 0 {
			return fmt.Errorf("ELF address range %#x+%d is not in a writable load segment", address, size)
		}
		return nil
	}
	return fmt.Errorf("ELF address range %#x+%d is outside the target's loadable image (it may be a stale runtime address captured with ASLR disabled)", address, size)
}

func (image *elfImage) validateAddress(address uint64, writable, executable bool) error {
	for _, load := range image.loads {
		if address < load.start || address >= load.end {
			continue
		}
		if writable && load.flags&elf.PF_W == 0 {
			return fmt.Errorf("ELF address %#x is not in a writable load segment", address)
		}
		if executable && load.flags&elf.PF_X == 0 {
			return fmt.Errorf("ELF address %#x is not in an executable load segment", address)
		}
		return nil
	}
	return fmt.Errorf("ELF address %#x is outside the target's loadable image (it may be a stale runtime address captured with ASLR disabled)", address)
}
