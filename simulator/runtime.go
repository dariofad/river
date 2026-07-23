package simulator

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/dariofad/river/manifest"
	"github.com/dariofad/river/my_types"
	"github.com/redis/go-redis/v9"
)

type runtimeDataDescriptor struct {
	Offset   uint64
	ModelID  uint32
	Size     uint32
	Type     uint32
	Category uint32
	Flags    uint32
	BaseKind uint32
}

type runtimeModelDescriptor struct {
	InputStart  uint32
	InputCount  uint32
	SampleStart uint32
	SampleCount uint32
	StateStart  uint32
	StateCount  uint32
	SampleEvery uint32
	MaxCycles   uint32
}

type runtimeValueKey struct {
	DataID uint32
	Cycle  uint32
}

type runtimeStateKey struct {
	ModelID uint32
	Cycle   uint32
	DataID  uint32
}

type runtimeRecord struct {
	Cycle   uint32
	ModelID uint32
	Values  []uint64
}

var errCycleLimit = errors.New("configured cycle limit reached")

func startPlan(
	plan *manifest.RuntimePlan,
	simulationMode my_types.Service,
	rawTrajectory map[string]interface{},
	errCh chan error,
	resCh chan my_types.OutputTrace,
	pertCh <-chan map[string]interface{},
	statePertCh <-chan []my_types.StateRecord,
	wg *sync.WaitGroup,
) {
	defer wg.Done()
	if plan == nil {
		errCh <- errors.New("server has no compiled manifest")
		return
	}
	spec, err := loadProbe()
	if err != nil {
		errCh <- fmt.Errorf("load eBPF collection: %w", err)
		return
	}
	objects := probeObjects{}
	if err := spec.LoadAndAssign(&objects, &ebpf.CollectionOptions{Programs: ebpf.ProgramOptions{LogLevel: 1, LogSizeStart: 20 * 1024 * 1024}}); err != nil {
		errCh <- fmt.Errorf("load eBPF objects: %w", err)
		return
	}
	defer objects.Close()

	cycles, err := configureRuntimeMaps(plan, rawTrajectory, &objects)
	if err != nil {
		errCh <- err
		return
	}
	CYCLES = cycles

	executable, err := link.OpenExecutable(plan.Binary)
	if err != nil {
		errCh <- fmt.Errorf("open model executable: %w", err)
		return
	}
	var links []link.Link
	defer func() {
		for _, attached := range links {
			_ = attached.Close()
		}
	}()
	for _, model := range plan.Models {
		cookie := uint64(model.ID) + 1
		entry, err := executable.Uprobe(model.WriteHook.Symbol, objects.UprobeModelEntry, &link.UprobeOptions{Cookie: cookie})
		if err != nil {
			errCh <- fmt.Errorf("attach %s perturbation hook: %w", model.Name, err)
			return
		}
		links = append(links, entry)
		sample, err := executable.Uretprobe(model.ReadHook.Symbol, objects.UprobeModelReturn, &link.UprobeOptions{Cookie: cookie})
		if err != nil {
			errCh <- fmt.Errorf("attach %s input/output read hook: %w", model.Name, err)
			return
		}
		links = append(links, sample)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if statePertCh != nil {
		go consumeNamedStates(ctx, plan, statePertCh, objects.RuntimeStateWriteMap, errCh)
	}
	if pertCh != nil {
		go consumeInputUpdates(ctx, plan, pertCh, objects.RuntimeTrajectoryMap, errCh)
	}

	reader, err := ringbuf.NewReader(objects.OutRb)
	if err != nil {
		errCh <- fmt.Errorf("open output ring buffer: %w", err)
		return
	}
	defer reader.Close()

	cmd := exec.CommandContext(ctx, plan.Binary)
	if VERBOSE {
		cmd.Stdout = os.Stdout
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		errCh <- fmt.Errorf("start model: %w", err)
		return
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	records, runErr := collectRuntimeRecords(ctx, plan, reader, done, simulationMode, cycles)
	if errors.Is(runErr, errCycleLimit) {
		cancel()
		runErr = <-done
	}
	if runErr != nil && !(cycles > 0 && cmdWasSigkilled(runErr)) {
		errCh <- runErr
		return
	}
	if resCh != nil {
		resCh <- recordsToOutput(plan, records)
	}
}

func configureRuntimeMaps(plan *manifest.RuntimePlan, raw map[string]interface{}, objects *probeObjects) (uint32, error) {
	cycles := plan.Cycles
	lookup, ambiguous := runtimeNames(plan)
	for key, value := range raw {
		data, ok, isAmbiguous := resolveRuntimeName(lookup, ambiguous, key)
		if !ok || isAmbiguous {
			return 0, fmt.Errorf("trajectory name %q is unknown or ambiguous; use the manifest path", key)
		}
		values, ok := value.([]interface{})
		if !ok {
			return 0, fmt.Errorf("trajectory %q is not an array", key)
		}
		if cycles == 0 {
			cycles = uint32(len(values))
		} else if len(values) > 0 && uint32(len(values)) != cycles {
			return 0, fmt.Errorf("trajectory %q has %d values, expected %d", key, len(values), cycles)
		}
		for cycle, value := range values {
			rawValue, err := encodePrimitive(value, data.Type)
			if err != nil {
				return 0, fmt.Errorf("trajectory %s[%d]: %w", key, cycle, err)
			}
			if err := objects.RuntimeTrajectoryMap.Update(runtimeValueKey{DataID: data.ID, Cycle: uint32(cycle)}, rawValue, ebpf.UpdateAny); err != nil {
				return 0, fmt.Errorf("load trajectory %s: %w", key, err)
			}
		}
	}
	for _, model := range plan.Models {
		all := append(append([]manifest.RuntimeData{}, model.Inputs...), model.Outputs...)
		all = append(all, model.States...)
		for _, data := range all {
			category := uint32(2)
			if data.Category == "input" {
				category = 0
			} else if data.Category == "output" {
				category = 1
			}
			flags := uint32(0)
			if trajectoryPresent(raw, lookup, data) {
				flags = 1
			}
			descriptor := runtimeDataDescriptor{Offset: uint64(data.Offset), ModelID: data.ModelID, Size: uint32(data.Type.Size), Type: primitiveCode(data.Type), Category: category, Flags: flags, BaseKind: uint32(data.Base)}
			if err := objects.RuntimeDataMap.Update(data.ID, descriptor, ebpf.UpdateAny); err != nil {
				return 0, fmt.Errorf("configure data %s: %w", data.Path, err)
			}
		}
		inputStart, sampleStart, stateStart := uint32(0), uint32(0), uint32(0)
		if len(model.Inputs) > 0 {
			inputStart, sampleStart = model.Inputs[0].ID, model.Inputs[0].ID
		} else if len(model.Outputs) > 0 {
			sampleStart = model.Outputs[0].ID
		}
		if len(model.States) > 0 {
			stateStart = model.States[0].ID
		}
		descriptor := runtimeModelDescriptor{InputStart: inputStart, InputCount: uint32(len(model.Inputs)), SampleStart: sampleStart, SampleCount: uint32(len(model.Inputs) + len(model.Outputs)), StateStart: stateStart, StateCount: uint32(len(model.States)), SampleEvery: plan.SampleEvery}
		if descriptor.SampleCount > 256 || descriptor.InputCount > 256 || descriptor.StateCount > 256 {
			return 0, fmt.Errorf("model %s selects more than 256 values in one category", model.Name)
		}
		if err := objects.RuntimeModelMap.Update(model.ID, descriptor, ebpf.UpdateAny); err != nil {
			return 0, fmt.Errorf("configure model %s: %w", model.Name, err)
		}
	}
	return cycles, nil
}

func trajectoryPresent(raw map[string]interface{}, lookup map[string]manifest.RuntimeData, data manifest.RuntimeData) bool {
	for name := range raw {
		candidate, ok, ambiguous := resolveRuntimeName(lookup, nil, name)
		if ok && !ambiguous && candidate.ID == data.ID {
			return true
		}
	}
	return false
}

func runtimeNames(plan *manifest.RuntimePlan) (map[string]manifest.RuntimeData, map[string]bool) {
	out := make(map[string]manifest.RuntimeData)
	ambiguous := make(map[string]bool)
	for _, model := range plan.Models {
		for _, data := range model.Inputs {
			for _, name := range []string{data.Path, model.Name + "." + data.Name, data.Name, strings.ToUpper(data.Name)} {
				if name == "" {
					continue
				}
				addRuntimeName(out, ambiguous, name, data)
				addRuntimeName(out, ambiguous, normalizeRuntimeName(name), data)
			}
		}
	}
	return out, ambiguous
}

func addRuntimeName(out map[string]manifest.RuntimeData, ambiguous map[string]bool, name string, data manifest.RuntimeData) {
	if name == "" {
		return
	}
	if existing, ok := out[name]; ok && existing.ID != data.ID {
		ambiguous[name] = true
	}
	out[name] = data
}

func resolveRuntimeName(lookup map[string]manifest.RuntimeData, ambiguous map[string]bool, name string) (manifest.RuntimeData, bool, bool) {
	if data, ok := lookup[name]; ok {
		return data, true, ambiguous != nil && ambiguous[name]
	}
	normalized := normalizeRuntimeName(name)
	data, ok := lookup[normalized]
	return data, ok, ambiguous != nil && ambiguous[normalized]
}

// normalizeRuntimeName makes Code Descriptor graphical labels (for example
// "Pedal Angle") compatible with the generated identifier ("PedalAngle").
func normalizeRuntimeName(name string) string {
	var normalized strings.Builder
	for _, char := range name {
		if unicode.IsLetter(char) || unicode.IsDigit(char) {
			normalized.WriteRune(unicode.ToLower(char))
		}
	}
	return normalized.String()
}

func collectRuntimeRecords(ctx context.Context, plan *manifest.RuntimePlan, reader *ringbuf.Reader, done <-chan error, mode my_types.Service, cycles uint32) ([]runtimeRecord, error) {
	var records []runtimeRecord
	completed := make(map[uint32]bool)
	redisClient := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
	defer redisClient.Close()
	processDone := false
	var processErr error
	for {
		reader.SetDeadline(time.Now().Add(100 * time.Millisecond))
		record, err := reader.Read()
		if err == nil {
			parsed, err := parseRuntimeRecord(record.RawSample)
			if err != nil {
				return nil, err
			}
			records = append(records, parsed)
			if cycles > 0 && parsed.Cycle+1 >= cycles {
				completed[parsed.ModelID] = true
				if len(completed) == len(plan.Models) {
					return records, errCycleLimit
				}
			}
			if mode == my_types.Monitoring && int(parsed.ModelID) < len(plan.Models) {
				values := make([]float64, len(parsed.Values))
				data := append(append([]manifest.RuntimeData{}, plan.Models[parsed.ModelID].Inputs...), plan.Models[parsed.ModelID].Outputs...)
				for i := range values {
					values[i] = decodePrimitive(parsed.Values[i], data[i].Type)
				}
				key := simulationRedisKey(plan.Models[parsed.ModelID].Name)
				_ = writeToRedis(ctx, redisClient, key, []my_types.ModelRecord{{Time: parsed.Cycle, Values: values}})
			}
			continue
		}
		if !processDone {
			select {
			case processErr = <-done:
				processDone = true
			default:
			}
		}
		if processDone {
			return records, processErr
		}
		select {
		case <-ctx.Done():
			return records, ctx.Err()
		default:
		}
	}
}

func parseRuntimeRecord(raw []byte) (runtimeRecord, error) {
	if len(raw) < 16 {
		return runtimeRecord{}, errors.New("truncated runtime record")
	}
	count := binary.LittleEndian.Uint32(raw[8:12])
	if count > 256 || len(raw) < 16+int(count)*8 {
		return runtimeRecord{}, errors.New("invalid runtime record length")
	}
	record := runtimeRecord{Cycle: binary.LittleEndian.Uint32(raw[0:4]), ModelID: binary.LittleEndian.Uint32(raw[4:8]), Values: make([]uint64, count)}
	for i := range record.Values {
		record.Values[i] = binary.LittleEndian.Uint64(raw[16+i*8 : 24+i*8])
	}
	return record, nil
}

func recordsToOutput(plan *manifest.RuntimePlan, records []runtimeRecord) my_types.OutputTrace {
	var output my_types.OutputTrace
	traces := make(map[uint32]*my_types.Trace)
	for _, model := range plan.Models {
		for _, data := range append(append([]manifest.RuntimeData{}, model.Inputs...), model.Outputs...) {
			trace := my_types.Trace{SignName: model.Name + "." + data.Name}
			traces[data.ID] = &trace
			output.Signals = append(output.Signals, trace)
		}
	}
	indexes := make(map[uint32]int)
	for i, signal := range output.Signals {
		for _, model := range plan.Models {
			for _, data := range append(append([]manifest.RuntimeData{}, model.Inputs...), model.Outputs...) {
				if signal.SignName == model.Name+"."+data.Name {
					indexes[data.ID] = i
				}
			}
		}
	}
	for _, record := range records {
		if int(record.ModelID) >= len(plan.Models) {
			continue
		}
		model := plan.Models[record.ModelID]
		data := append(append([]manifest.RuntimeData{}, model.Inputs...), model.Outputs...)
		for i, raw := range record.Values {
			if i < len(data) {
				index := indexes[data[i].ID]
				output.Signals[index].Values = append(output.Signals[index].Values, decodePrimitive(raw, data[i].Type))
			}
		}
	}
	_ = traces
	return output
}

func consumeNamedStates(ctx context.Context, plan *manifest.RuntimePlan, in <-chan []my_types.StateRecord, target *ebpf.Map, errCh chan<- error) {
	for {
		select {
		case <-ctx.Done():
			return
		case records, ok := <-in:
			if !ok {
				return
			}
			for _, record := range records {
				state, ok := plan.StateByName[record.State]
				if !ok {
					errCh <- fmt.Errorf("state %q is unknown or disabled", record.State)
					return
				}
				value, err := encodePrimitive(record.Value, state.Type)
				if err != nil {
					errCh <- fmt.Errorf("state %s: %w", record.State, err)
					return
				}
				key := runtimeStateKey{ModelID: state.ModelID, Cycle: record.Time, DataID: state.ID}
				if err := target.Update(key, value, ebpf.UpdateAny); err != nil {
					errCh <- fmt.Errorf("schedule state %s: %w", record.State, err)
					return
				}
			}
		}
	}
}

func consumeInputUpdates(ctx context.Context, plan *manifest.RuntimePlan, in <-chan map[string]interface{}, target *ebpf.Map, errCh chan<- error) {
	lookup, ambiguous := runtimeNames(plan)
	for {
		select {
		case <-ctx.Done():
			return
		case update, ok := <-in:
			if !ok {
				return
			}
			times, ok := update["time"].([]interface{})
			if !ok {
				errCh <- errors.New("live input update requires a time array")
				return
			}
			for name, rawValues := range update {
				if name == "time" {
					continue
				}
				data, known, isAmbiguous := resolveRuntimeName(lookup, ambiguous, name)
				values, array := rawValues.([]interface{})
				if !known || isAmbiguous || !array || len(values) != len(times) {
					errCh <- fmt.Errorf("invalid live input update %q", name)
					return
				}
				for i := range times {
					cycle, err := integerValue(times[i])
					if err != nil {
						errCh <- err
						return
					}
					value, err := encodePrimitive(values[i], data.Type)
					if err != nil {
						errCh <- err
						return
					}
					if err := target.Update(runtimeValueKey{DataID: data.ID, Cycle: uint32(cycle)}, value, ebpf.UpdateAny); err != nil {
						errCh <- err
						return
					}
				}
			}
		}
	}
}

func encodePrimitive(value interface{}, typ manifest.PrimitiveType) (uint64, error) {
	if typ.Boolean {
		if b, ok := value.(bool); ok {
			if b {
				return 1, nil
			}
			return 0, nil
		}
	}
	number, err := numericValue(value)
	if err != nil {
		return 0, err
	}
	if typ.Floating {
		if typ.Size == 4 {
			converted := float32(number)
			if math.IsInf(float64(converted), 0) && !math.IsInf(number, 0) {
				return 0, fmt.Errorf("%v overflows float32", value)
			}
			return uint64(math.Float32bits(converted)), nil
		}
		return math.Float64bits(number), nil
	}
	if typ.Boolean {
		if number == 0 {
			return 0, nil
		}
		if number == 1 {
			return 1, nil
		}
		return 0, fmt.Errorf("%v is not a Boolean value", value)
	}
	if math.Trunc(number) != number {
		return 0, fmt.Errorf("%v is not an integer", value)
	}
	bits := uint(typ.Size) * 8
	if typ.Signed {
		minimum := -math.Pow(2, float64(bits-1))
		maximum := math.Pow(2, float64(bits-1)) - 1
		if number < minimum || number > maximum {
			return 0, fmt.Errorf("%v is outside %s range", value, typ.Name)
		}
		return uint64(int64(number)), nil
	}
	maximum := math.Pow(2, float64(bits)) - 1
	if number < 0 || number > maximum {
		return 0, fmt.Errorf("%v is outside %s range", value, typ.Name)
	}
	return uint64(number), nil
}

func decodePrimitive(raw uint64, typ manifest.PrimitiveType) float64 {
	if typ.Boolean {
		if raw != 0 {
			return 1
		}
		return 0
	}
	if typ.Floating {
		if typ.Size == 4 {
			return float64(math.Float32frombits(uint32(raw)))
		}
		return math.Float64frombits(raw)
	}
	bits := typ.Size * 8
	if typ.Signed && bits < 64 {
		shift := 64 - bits
		return float64(int64(raw<<shift) >> shift)
	}
	if typ.Signed {
		return float64(int64(raw))
	}
	return float64(raw)
}

func primitiveCode(typ manifest.PrimitiveType) uint32 {
	if typ.Boolean {
		return 1
	}
	if typ.Floating && typ.Size == 4 {
		return 2
	}
	if typ.Floating {
		return 3
	}
	if typ.Signed {
		return 4
	}
	return 5
}

func numericValue(value interface{}) (float64, error) {
	rv := reflect.ValueOf(value)
	if !rv.IsValid() {
		return 0, errors.New("value is null")
	}
	switch rv.Kind() {
	case reflect.Float32, reflect.Float64:
		return rv.Convert(reflect.TypeOf(float64(0))).Float(), nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return float64(rv.Int()), nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return float64(rv.Uint()), nil
	default:
		return 0, fmt.Errorf("%T is not numeric", value)
	}
}

func integerValue(value interface{}) (uint64, error) {
	n, err := numericValue(value)
	if err != nil || n < 0 || math.Trunc(n) != n {
		return 0, fmt.Errorf("invalid cycle value %v", value)
	}
	return uint64(n), nil
}
