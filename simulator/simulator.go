package simulator

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"log"
	"math"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/dariofad/ebpf_simulator/my_types"
	"github.com/redis/go-redis/v9"
)

var VERBOSE bool
var RATIO uint32
var CYCLES uint32
var INTERACTIVE uint16

type eBPFInjector struct {
	probeObjs *probeObjects
}

func (*eBPFInjector) Inject() {

}

// Allow the simulator process to lock memory for eBPF resources
func RemoveMemlock() {

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}
}

// Utility, based on the standard 4096-byte page
func paddedEntries(entries uint32) uint32 {

	return uint32(((entries + 4096 - 1) / 4096) * 4096)
}

func setCycles(spec *ebpf.CollectionSpec, simData my_types.SimFormat) error {

	// set ratio
	ratio, err := strconv.ParseUint(simData.MinorToMajorRatio, 10, 64) // base 10
	if err != nil {
		log.Printf("Error converting MinorToMinorRatio: %s", err)
		return err
	}
	RATIO = uint32(ratio)
	if err = spec.Variables["MINOR_TO_MAJOR_RATIO"].Set(RATIO); err != nil {
		log.Printf("Error setting MinorToMajorRation in spec: %s", err)
		return err
	}
	log.Printf("Minor_to_major_ratio :%d", RATIO)

	// set cycles
	cycles, err := strconv.ParseUint(simData.NofCycles, 10, 64) // base 10
	if err != nil {
		log.Printf("Error converting Cycles: %s", err)
		return err
	}
	CYCLES = uint32(cycles)
	if err = spec.Variables["MAX_CYCLES"].Set(CYCLES); err != nil {
		log.Printf("Error setting Cycles in spec: %s", err)
		return err
	}
	log.Printf("Cycles: %d", CYCLES)

	return nil
}

// Converts raw simulation data to a proper trajectory
func extractTrajectory(rawTrajectory map[string]interface{}, simData my_types.SimFormat) (map[string][]float64, error) {

	trajectory := make(map[string][]float64)
	for _, signal := range simData.WTimingI.Signals {
		vals := make([]float64, CYCLES)
		if rawTrajectory, ok := rawTrajectory[signal.SignName].([]interface{}); ok {
			for t, rawVal := range rawTrajectory {
				val, ok := rawVal.(float64)
				if !ok {
					log.Printf("Cannot convert to float trajectory value %v", rawVal)
					return nil, errors.New("Cannot convert trajectory value to float64")
				}
				vals[t] = val
			}
		} else {
			log.Printf("Cannot extract raw trajectory for signal %s", signal.SignName)
			return nil, errors.New("Trajectory extraction error")
		}
		trajectory[signal.SignName] = vals
	}
	return trajectory, nil
}

func Start(
	simulationMode my_types.Service,
	rawTrajectory map[string]interface{},
	errCh chan error,
	resCh chan my_types.OutputTrace,
	pertCh <-chan map[string]interface{},
	statePertCh <-chan []my_types.StateRecord,
	wg *sync.WaitGroup,
) {

	// Load eBPF collection spec
	spec, err := loadProbe()
	if err != nil {
		log.Printf("loading collectionSpec: %s", err)
		errCh <- errors.New("Simulation failed: cannot retrieve collection spec")
		wg.Done()
		return
	}

	// Read the simulation data from the configuration file
	rawSimData, err := os.ReadFile("simulator/config.json")
	if err != nil {
		log.Print("Error reading the configuration")
		errCh <- errors.New("Simulation failed: cannot read the configuration file")
		wg.Done()
		return
	}
	var simData my_types.SimFormat
	err = json.Unmarshal(rawSimData, &simData)

	// Set cycles in ebpf
	err = setCycles(spec, simData)
	if err != nil {
		errCh <- err
		wg.Done()
		return
	}

	// Fix max entries in eBPF spec, retrieve signals and categories
	var sCategories []my_types.SignTiming
	sCategories = append(sCategories, simData.WTimingI)
	sCategories = append(sCategories, simData.RTimingI)
	sCategories = append(sCategories, simData.RTimingO)
	var sTypes []uint32
	for t := 0; t < len(simData.WTimingI.Signals); t++ {
		sTypes = append(sTypes, 0)
	}
	var _nof_wi, _nof_ri, _nof_ro uint32
	_nof_wi = uint32(len(simData.WTimingI.Signals))
	_nof_ri = uint32(len(simData.RTimingI.Signals))
	_nof_ro = uint32(len(simData.RTimingO.Signals))
	log.Printf("nof_wi %d, nof_ri %d, nof_ro %d", _nof_wi, _nof_ri, _nof_ro)
	if err = spec.Variables["NOF_WISIGNALS"].Set(uint32(len(simData.WTimingI.Signals))); err != nil {
		log.Printf("Error setting variable setting variable NOF_WISIGNALS: %v", err)
		errCh <- err
		wg.Done()
		return
	}
	for t := 0; t < len(simData.RTimingI.Signals); t++ {
		sTypes = append(sTypes, 1)
	}
	if err = spec.Variables["NOF_RISIGNALS"].Set(uint32(len(simData.RTimingI.Signals))); err != nil {
		log.Printf("Error setting variable setting variable NOF_RISIGNALS: %v", err)
		errCh <- err
		wg.Done()
		return
	}
	for t := 0; t < len(simData.RTimingO.Signals); t++ {
		sTypes = append(sTypes, 2)
	}
	if err = spec.Variables["NOF_ROSIGNALS"].Set(uint32(len(simData.RTimingO.Signals))); err != nil {
		log.Printf("Error setting variable setting variable NOF_ROSIGNALS: %v", err)
		errCh <- err
		wg.Done()
		return
	}

	// create the probeObjects
	probeObjs := probeObjects{}
	// Load eBPF objects (maps + programs) into the kernel
	if err := spec.LoadAndAssign(&probeObjs, &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel:     1,
			LogSizeStart: 20 * 1024 * 1024,
		},
	}); err != nil {
		log.Printf("Cannot load eBPF objects, err: %s", err)
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			log.Printf("Verifier error: %+v", ve)
		}
		errCh <- err
		wg.Done()
		return
	}
	defer probeObjs.Close()

	// Extract trajectory
	trajectory, err := extractTrajectory(rawTrajectory, simData)
	if err != nil {
		errCh <- err
		wg.Done()
		return
	}
	log.Print("Input trajectory extracted successfully")

	// get trace map specs
	traceeMapSpec := spec.Maps["tracee_map"]
	traceeMapSpec.MaxEntries = paddedEntries(uint32(len(sTypes)))
	// create outer map
	traceeMap := probeObjs.TraceeMap
	if err != nil {
		log.Printf("Cannot create mSignals (outer) map: %s", err)
		errCh <- err
		wg.Done()
		return
	}
	// create signal traces
	// start preparing a template for the array positions
	innerMapKeys := make([]uint32, CYCLES)
	for p, _ := range innerMapKeys {
		innerMapKeys[p] = uint32(p)
	}
	for s := 0; s < len(sTypes); s++ {
		// refine and clone the inner map spec to avoid reuse
		innerSpec := traceeMapSpec.InnerMap.Copy()
		innerSpec.MaxEntries = paddedEntries(CYCLES)
		inner, err := ebpf.NewMap(innerSpec)
		if err != nil {
			log.Printf("Cannot create mSignal (inner) map: %s", err)
			errCh <- err
			wg.Done()
			return
		}
		// pin the inner map
		pinPath := "/sys/fs/bpf/inner_values_" + strconv.FormatInt(int64(s), 10)
		if err := inner.Pin(pinPath); err != nil {
			log.Printf("Cannot pin inner map at %v", pinPath)
			errCh <- err
			wg.Done()
			return
		}
		// inject the trajectory
		if s < int(_nof_wi) { // only for signals to write
			sName := simData.WTimingI.Signals[s].SignName
			// set the trajectory with a batch update
			_, err = inner.BatchUpdate(innerMapKeys, trajectory[sName], &ebpf.BatchOptions{
				Flags: uint64(ebpf.UpdateAny),
			})
			if err != nil {
				log.Printf("Injection of trajectory failed, %v", err)
				errCh <- errors.New("Trajectory injection failure")
				wg.Done()
				return
			}
			log.Printf("Input trajectory %d successfully injected", s)
		}
		// insert single trace map into tracees
		key := uint32(s)
		fd := inner.FD()
		value := uint32(fd)
		if err := traceeMap.Update(key, value, 0); err != nil {
			if errno, ok := err.(syscall.Errno); ok {
				log.Printf("KERNEL ERROR: errno=%d", errno)
			} else {
				log.Printf("ERROR: %v", err)
			}
			log.Printf("Failed to insert FD for signal %d: %s", s, err)
			errCh <- err
			wg.Done()
			return
		}
		// defer inner map pinning
		// Now, unpin the map
		defer func() {
			if err := inner.Unpin(); err != nil {
				log.Printf("Cannot unpin inner map, err: %v", err)
			}
			log.Printf("Map unpinned from %s", pinPath)
		}()
		defer inner.Close()
	}

	// setup signal addresses and types
	mAddressSpec := spec.Maps["address_map"]
	mAddressSpec.MaxEntries = paddedEntries(uint32(len(sTypes)))
	mTypesSpec := spec.Maps["type_map"]
	mTypesSpec.MaxEntries = paddedEntries(uint32(len(sTypes)))
	var skey uint32 = 0
	for _, sCategory := range sCategories {
		for _, signal := range sCategory.Signals {
			// address
			signalAddr, err := strconv.ParseUint(signal.SignAddr, 16, 64)
			if err != nil {
				log.Printf("Error converting signal address: %s", err)
				errCh <- err
				wg.Done()
				return
			}
			err = probeObjs.AddressMap.Update(skey, signalAddr, 0)
			if err != nil {
				log.Printf("Cannot perform the update to addressMap: %v", err)
				errCh <- err
				wg.Done()
				return
			}
			// type
			err = probeObjs.TypeMap.Update(skey, sTypes[skey], 0)
			skey += 1
		}
	}

	// Determine interactivity
	if simulationMode == my_types.Falsification {
		INTERACTIVE = 0
	} else {
		INTERACTIVE = 1
	}
	if probeObjs.InteractiveMap.Update(uint32(0), uint16(INTERACTIVE), 0); err != nil {
		log.Printf("Error setting interactivity: %s", err)
		errCh <- err
		wg.Done()
		return
	}

	// Open model executable
	modelExecutable, err := link.OpenExecutable(simData.ModelPath)
	if err != nil {
		log.Fatalf("Error opening model executable: %s", err)
		errCh <- err
		wg.Done()
		return
	}

	// Link all uprobes
	var offset uint64
	// 1) writes on input signals
	if _nof_wi > 0 {
		offset, err = strconv.ParseUint(simData.WTimingI.Offset, 10, 64) // base 10
		if err != nil {
			log.Printf("Error converting uprobe offset: %s", err)
			errCh <- err
			wg.Done()
			return
		}
		uprobe_wi, err := modelExecutable.Uprobe(
			simData.WTimingI.SymbolName,
			probeObjs.UprobeWriteI,
			&link.UprobeOptions{Offset: offset},
		)
		if err != nil {
			log.Printf("Error setting the uprobe_wi: %v", err)
			errCh <- err
			wg.Done()
			return
		} else {
			log.Print("Uprobe_wi linked")
		}
		defer uprobe_wi.Close()
	}
	// 2) reads on input signals
	if _nof_ri > 0 {
		offset, err = strconv.ParseUint(simData.RTimingI.Offset, 10, 64) // base 10
		if err != nil {
			log.Printf("Error converting uprobe offset: %s", err)
			errCh <- err
			wg.Done()
			return
		}
		uprobe_ri, err := modelExecutable.Uprobe(
			simData.RTimingI.SymbolName,
			probeObjs.UprobeReadI,
			&link.UprobeOptions{Offset: offset},
		)
		if err != nil {
			log.Printf("Error setting the uprobe_ri: %v", err)
			errCh <- err
			wg.Done()
			return
		} else {
			log.Print("Uprobe_ri linked")
		}
		defer uprobe_ri.Close()
	}
	// 3) reads on output signals
	if _nof_ro > 0 {
		offset, err = strconv.ParseUint(simData.RTimingO.Offset, 10, 64) // base 10
		if err != nil {
			log.Printf("Error converting uprobe offset: %s", err)
			errCh <- err
			wg.Done()
			return
		}
		uprobe_ro, err := modelExecutable.Uprobe(
			simData.RTimingO.SymbolName,
			probeObjs.UprobeReadO,
			&link.UprobeOptions{Offset: offset},
		)
		if err != nil {
			log.Printf("Error setting the uprobe_ro: %v", err)
			errCh <- err
			wg.Done()
			return
		} else {
			log.Print("Uprobe_ro linked")
		}
		defer uprobe_ro.Close()
	}
	// cyclic timer
	uprobe_timer, err := modelExecutable.Uprobe(simData.TimerSymbol, probeObjs.UprobeTimer, nil)
	defer uprobe_timer.Close()

	// Start preparing the simulation commands
	ctx, cancelSimulation := context.WithCancel(context.Background())
	defer cancelSimulation()
	binCmd := exec.CommandContext(ctx, simData.ModelPath)
	if VERBOSE {
		binCmd.Stdout = os.Stdout
	}
	binCmd.Stderr = os.Stderr
	// Start the command
	log.Print("Starting simulation")
	if err := binCmd.Start(); err != nil {
		log.Printf("Failed to start simulation command: %s", err)
		errCh <- err
		wg.Done()
		return
	}

	// wait for non-interactive simulations to terminate
	if simulationMode == my_types.Falsification {
		// wait until simulation terminates
		if err := binCmd.Wait(); err != nil {
			if !cmdWasSigkilled(err) {
				log.Printf("Simulation finished with error: %s", err)
				errCh <- err
				wg.Done()
				return
			}
		} else {
			log.Print("Simulation completed successfully")
		}
	} else {
		// don't wait until it terminates
		log.Printf("Simulation is running...")
	}

	switch simulationMode {
	case my_types.Monitoring:
		ctx := context.Background()
		if err := monitorSimulation(ctx, probeObjs, _nof_ro); err != nil {
			errCh <- err
			wg.Done()
			return
		}
	case my_types.Falsification:
		var outSignals my_types.OutputTrace
		for id, signal := range simData.RTimingO.Signals {
			var signTrace my_types.Trace
			signTrace.SignName = signal.SignName
			var signalKey uint32 = uint32(id) + _nof_wi + _nof_ri
			// get the trace from the eBPF map
			pinPath := "/sys/fs/bpf/inner_values_" + strconv.FormatInt(int64(signalKey), 10)
			innerTrace, err := ebpf.LoadPinnedMap(pinPath, nil)
			if err != nil {
				log.Printf("Cannot recover inner pinned map at %s: %v", pinPath, err)
				errCh <- err
				wg.Done()
				return
			}
			defer innerTrace.Close()
			// trace extraction
			values := make([]float64, CYCLES)
			for pos := uint32(0); pos < CYCLES; pos++ {
				err := innerTrace.Lookup(&pos, &values[pos])
				if err != nil {
					log.Printf("Trace lookup failed: %s\n", err)
					errCh <- err
					wg.Done()
					return
				}
			}
			signTrace.Values = values
			//log.Printf("values %v", values)
			outSignals.Signals = append(outSignals.Signals, signTrace)
		}
		//log.Printf("outsignals %v", outSignals)
		resCh <- outSignals
	case my_types.StatePerturbation:
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		wgm := &sync.WaitGroup{}
		wgm.Add(1)
		errChm := make(chan error, 1)
		defer close(errChm)
		errChi := make(chan error, 1)
		defer close(errChi)
		// pin the user space ringbuf
		pertRBPath := "/sys/fs/bpf/state_pertbuf"
		if err := probeObjs.StateRb.Pin(pertRBPath); err != nil {
			log.Printf("Cannot pin state perturbation buffer at %v", pertRBPath)
			errCh <- err
			wg.Done()
			return
		}
		// defer unpinnning
		defer func() {
			if err := probeObjs.StateRb.Unpin(); err != nil {
				log.Printf("Cannot unpin state perturbation buffer: %v", err)
			}
		}()

		// apply state perturbation
		go func(ctx context.Context, statePertCh <-chan []my_types.StateRecord, probeObjs probeObjects, errCh chan error) {

			for {
				select {
				case <-ctx.Done():
					return
				case perturbation := <-statePertCh:
					// write records to a temp file
					tempFile, err := os.CreateTemp("", "model_state_records_*.bin")
					if err != nil {
						log.Printf("Cannot create temporary inject file for state records: %v", err)
						break
					}
					defer tempFile.Close()
					for _, r := range perturbation {
						binary.Write(tempFile, binary.LittleEndian, r.Time)
						binary.Write(tempFile, binary.LittleEndian, r.ValueSize)
						binary.Write(tempFile, binary.LittleEndian, r.Addr)
						binary.Write(tempFile, binary.LittleEndian, r.Value)
					}

					// call the injector
					enableInjectorVerbosity := "0"
					if VERBOSE {
						enableInjectorVerbosity = "1"
					}
					injCmd := exec.Command(
						"sudo",
						"./simulator/state_injector",
						tempFile.Name(),
						enableInjectorVerbosity,
					)
					injCmd.Stdout = os.Stdout
					injCmd.Stderr = os.Stderr
					if err = injCmd.Run(); err != nil {
						log.Printf("Injector cmd failed: %v", err)
						break
					}
				}

			}
		}(ctx, statePertCh, probeObjs, errChi)

		// monitor simulation
		go asyncMonitorSimulation(wgm, errChm, ctx, probeObjs, _nof_ro)

		// wait for simulation to terminate
		wgm.Wait()
		// return the error if occured, otherwise send simulation task terminated
		select {
		case err := <-errCh:
			errCh <- err
		default:
			wg.Done()
		}
		return

	case my_types.SignalPerturbation:
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		wgm := &sync.WaitGroup{}
		wgm.Add(1)
		errChm := make(chan error, 1)
		defer close(errChm)
		errChi := make(chan error, 1)
		defer close(errChi)
		// pin the user space ringbuf
		pertRBPath := "/sys/fs/bpf/pertbuf"
		if err := probeObjs.InjRb.Pin(pertRBPath); err != nil {
			log.Printf("Cannot pin perturbation buffer at %v", pertRBPath)
			errCh <- err
			wg.Done()
			return
		}
		// defer unpinnning
		defer func() {
			if err := probeObjs.InjRb.Unpin(); err != nil {
				log.Printf("Cannot unpin perturbation buffer: %v", err)
			}
		}()

		// apply signal perturbation
		go func(ctx context.Context, pertCh <-chan map[string]interface{}, probeObjs probeObjects, errCh chan error, _nof_wi uint32) {

			for {
				select {
				case <-ctx.Done():
					return
				case perturbation := <-pertCh:
					// extract perturbation records
					pertRecords, err := extractPerturbationRecords(perturbation, simData)
					if err != nil {
						log.Printf("Error converting perturbation into model input records: %v", err)
					}
					// write records to a temp file (todo: improve)
					tempFile, err := os.CreateTemp("", "model_records_*.bin")
					if err != nil {
						log.Printf("Cannot create temporary inject file: %v", err)
						break
					}
					defer tempFile.Close()
					for _, r := range pertRecords {
						binary.Write(tempFile, binary.LittleEndian, r.Time)
						binary.Write(tempFile, binary.LittleEndian, r.Filler)
						for _, v := range r.Values {
							binary.Write(tempFile, binary.LittleEndian, math.Float64bits(v))
						}
					}

					// call the injector
					enableInjectorVerbosity := "0"
					if VERBOSE {
						enableInjectorVerbosity = "1"
					}
					injCmd := exec.Command(
						"sudo",
						"./simulator/injector",
						strconv.FormatInt(int64(_nof_wi), 10),
						tempFile.Name(),
						enableInjectorVerbosity,
					)
					injCmd.Stdout = os.Stdout
					injCmd.Stderr = os.Stderr
					if err = injCmd.Run(); err != nil {
						log.Printf("Injector cmd failed: %v", err)
						break
					}
				}

			}
		}(ctx, pertCh, probeObjs, errChi, _nof_wi)
		// monitor simulation
		go asyncMonitorSimulation(wgm, errChm, ctx, probeObjs, _nof_ro)

		// wait for simulation to terminate
		wgm.Wait()
		// return the error if occured, otherwise send simulation task terminated
		select {
		case err := <-errCh:
			errCh <- err
		default:
			wg.Done()
		}
		return
	}

	// terminate
	wg.Done()
	return
}

func customConversion(rawVal interface{}) (uint32, bool) {

	var val uint32
	val, ok := rawVal.(uint32)
	if ok {
		return val, true
	} else {
		_v, ok := rawVal.(uint16)
		if ok {
			return uint32(_v), true
		} else {
			_v, ok := rawVal.(uint8)
			if ok {
				return uint32(_v), true
			}
		}
	}
	vali, ok := rawVal.(int32)
	if ok {
		return uint32(vali), true
	} else {
		_v, ok := rawVal.(int16)
		if ok {
			return uint32(_v), true
		} else {
			_v, ok := rawVal.(int8)
			if ok {
				return uint32(_v), true
			}
		}
	}

	log.Printf("Cannot convert to integer time value %v", rawVal)
	return 0, false

}

func extractPerturbationRecords(data map[string]interface{}, simData my_types.SimFormat) ([]my_types.ModelRecord, error) {

	// extract time
	timeVals := make([]uint32, 0)
	if rawTime, ok := data["time"].([]interface{}); ok {
		for _, rawVal := range rawTime {
			var val uint32
			val, ok := customConversion(rawVal)
			if !ok {
				return nil, errors.New("Cannot convert perturbation time value to integer")
			}
			timeVals = append(timeVals, val)
		}
	} else {
		log.Print("Cannot extract raw values for time")
		return nil, errors.New("Perturbation extraction error")
	}
	signalVals := make(map[string][]float64, 0)
	// extract signals
	for signal := range data {
		if signal == "time" {
			continue
		}
		vals := make([]float64, 0)
		if rawSignal, ok := data[signal].([]interface{}); ok {
			for _, rawVal := range rawSignal {
				val, ok := rawVal.(float64)
				if !ok {
					log.Print("Cannot convert to float64 value %v", rawVal)
					return nil, errors.New("Cannot convert perturbation value to float64")
				}
				vals = append(vals, val)
			}
		} else {
			log.Print("Cannot extract raw values for %v", signal)
			return nil, errors.New("Perturbation extraction error")
		}
		signalVals[signal] = vals
	}
	// pack into model records and return
	pertRecords := make([]my_types.ModelRecord, 0)
	for p, v := range timeVals {
		var record my_types.ModelRecord
		record.Time = v
		record.Filler = 0
		record.Values = make([]float64, len(simData.WTimingI.Signals))
		for signal_pos, signal := range simData.WTimingI.Signals {
			if vals, ok := signalVals[signal.SignName]; ok {
				record.Values[signal_pos] = vals[p]
			} else {
				// append zero
				record.Values = append(record.Values, 0)
			}
		}
		pertRecords = append(pertRecords, record)
	}
	return pertRecords, nil
}

func asyncMonitorSimulation(wg *sync.WaitGroup, errCh chan<- error, ctx context.Context, probeObjs probeObjects, _nof_ro uint32) {

	defer wg.Done()
	err := monitorSimulation(ctx, probeObjs, _nof_ro)
	errCh <- err
}

func monitorSimulation(ctx context.Context, probeObjs probeObjects, _nof_ro uint32) error {

	// Create the Redis client
	redisClient := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
	// Get the simulation id
	simulationId := strconv.Itoa(0) // todo fix
	// Add a new Redis set fot the current run
	if err := redisClient.SAdd(ctx, "simulation", simulationId).Err(); err != nil {
		log.Print("Failed to add simulation set to Redis:", err)
		return errors.New("Error adding new simulation set to Redis")
	}
	// Create a ring buffer reader
	rbReader, err := ringbuf.NewReader(probeObjs.OutRb)
	if err != nil {
		log.Printf("Failed to create ring buffer reader: %v", err)
		return errors.New("Error creating the ring buffer reader")
	}
	defer rbReader.Close()
	// Read events from the ring buffer and write them to Redis
	var records []my_types.ModelRecord
	var writtenRecords uint32 = 0
	simulationKey := "simulation:" + simulationId
	for {
		rbReader.SetDeadline(time.Now().Add(50 * time.Millisecond))
		record, err := rbReader.Read()
		if err == nil {

			// check record validity
			raw := record.RawSample
			if len(raw) < int((_nof_ro+1)*8) {
				log.Printf("Corrupted record: truncated to %d bytes", len(raw))
			}
			// convert to a structured record
			_vals := make([]float64, _nof_ro)
			for p, _ := range _vals {
				_tbuf := bytes.NewReader(raw[8+p*8 : 16+p*8])
				binary.Read(_tbuf, binary.LittleEndian, &_vals[p])
			}
			oRec := my_types.ModelRecord{
				Time:   binary.LittleEndian.Uint32(raw),
				Values: _vals,
			}
			records = append(records, oRec)
		} else if writtenRecords+uint32(len(records)) == CYCLES {
			// Terminate
			break
		}
		if len(records) >= 50 {
			if err = writeToRedis(ctx, redisClient, simulationKey, records); err != nil {
				return errors.New("Error writing records to Redis")
			}
			// Empty local record slice
			writtenRecords += uint32(len(records))
			records = []my_types.ModelRecord{}
		}
	}
	if len(records) != 0 {
		// Flush last records
		if err = writeToRedis(ctx, redisClient, simulationKey, records); err != nil {
			return errors.New("Error writing records to Redis")
		}
		// Empty local record slice
		writtenRecords += uint32(len(records))
		records = []my_types.ModelRecord{}
	}

	return nil
}

// Writes a slice of records to Redis
func writeToRedis(ctx context.Context, redisClient *redis.Client, simulationKey string, records []my_types.ModelRecord) error {

	// convert records to string representation and add them to a Redis sorted set
	var z []redis.Z
	for _, rec := range records {
		z = append(z, redis.Z{Score: float64(rec.Time), Member: my_types.ModelRecordToCSVString(rec)})
	}
	// push records to Redis
	if n, err := redisClient.ZAdd(ctx, simulationKey, z...).Result(); err != nil {
		log.Printf("Failed to write batch for simulation: %v", err)
		return err
	} else {
		log.Printf("Uploaded to Redis %d records", n)
	}

	return nil
}

func cmdWasSigkilled(err error) bool {

	if err == nil {
		return false
	}
	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		return false
	}
	status, ok := exitErr.Sys().(syscall.WaitStatus)
	if !ok {
		return false
	}
	return status.Signaled() && status.Signal() == syscall.SIGKILL
}
