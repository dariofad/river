package simulator

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"log"
	"os"
	"os/exec"
	"strconv"
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
	log.Printf("Cycles :%d", CYCLES)

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
					log.Print("Cannot convert to float trajectory value %v", rawVal)
					return nil, errors.New("Cannot convert trajectory value to float64")
				}
				vals[t] = val
			}
		} else {
			log.Print("Cannot extract raw trajectory for signal %s", signal.SignName)
			return nil, errors.New("Trajectory extraction error")
		}
		trajectory[signal.SignName] = vals
	}
	return trajectory, nil
}

// todo: return a handler to the caller to enable enforcement
func Start(simulationMode my_types.Service, rawTrajectory map[string]interface{}) (*my_types.OutputTrace, error) {

	// Load eBPF collection spec
	spec, err := loadProbe()
	if err != nil {
		log.Printf("loading collectionSpec: %s", err)
		return nil, errors.New("Simulation failed: cannot retrieve collection spec")
	}

	// Read the simulation data from the configuration file
	rawSimData, err := os.ReadFile("simulator/config.json")
	if err != nil {
		log.Print("Error reading the configuration")
		return nil, errors.New("Simulation failed: cannot read the configuration file")
	}
	var simData my_types.SimFormat
	err = json.Unmarshal(rawSimData, &simData)

	// Set cycles in ebpf
	err = setCycles(spec, simData)
	if err != nil {
		return nil, err
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
		return nil, err
	}
	for t := 0; t < len(simData.RTimingI.Signals); t++ {
		sTypes = append(sTypes, 1)
	}
	if err = spec.Variables["NOF_RISIGNALS"].Set(uint32(len(simData.RTimingI.Signals))); err != nil {
		log.Printf("Error setting variable setting variable NOF_RISIGNALS: %v", err)
		return nil, err
	}
	for t := 0; t < len(simData.RTimingO.Signals); t++ {
		sTypes = append(sTypes, 2)
	}
	if err = spec.Variables["NOF_ROSIGNALS"].Set(uint32(len(simData.RTimingO.Signals))); err != nil {
		log.Printf("Error setting variable setting variable NOF_ROSIGNALS: %v", err)
		return nil, err
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
		return nil, err
	}
	defer probeObjs.Close()

	// Extract trajectory
	trajectory, err := extractTrajectory(rawTrajectory, simData)
	if err != nil {
		return nil, err
	}
	log.Print("Input trajectory extracted successfully")

	// get trace map specs
	traceeMapSpec := spec.Maps["tracee_map"]
	traceeMapSpec.MaxEntries = paddedEntries(uint32(len(sTypes)))
	// create outer map
	traceeMap := probeObjs.TraceeMap
	if err != nil {
		log.Printf("Cannot create mSignals (outer) map: %s", err)
		return nil, err
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
			return nil, err
		}
		// pin the inner map
		pinPath := "/sys/fs/bpf/inner_values_" + strconv.FormatInt(int64(s), 10)
		if err := inner.Pin(pinPath); err != nil {
			log.Printf("Cannot pin inner map at %v", pinPath)
			return nil, err
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
				return nil, errors.New("Trajectory injection failure")
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
			return nil, err
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
				return nil, err
			}
			err = probeObjs.AddressMap.Update(skey, signalAddr, 0)
			if err != nil {
				log.Printf("Cannot perform the update to addressMap: %v", err)
				return nil, err
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
	if probeObjs.InteractiveMap.Update(uint32(0), uint16(1), 0); err != nil {
		log.Printf("Error setting interactivity: %s", err)
		return nil, err
	}

	// Open model executable
	modelExecutable, err := link.OpenExecutable(simData.ModelPath)
	if err != nil {
		log.Fatalf("Error opening model executable: %s", err)
		return nil, err
	}

	// Link all uprobes
	var offset uint64
	// 1) writes on input signals
	if _nof_wi > 0 {
		offset, err = strconv.ParseUint(simData.WTimingI.Offset, 10, 64) // base 10
		if err != nil {
			log.Printf("Error converting uprobe offset: %s", err)
			return nil, err
		}
		uprobe_wi, err := modelExecutable.Uprobe(
			simData.WTimingI.SymbolName,
			probeObjs.UprobeWriteI,
			&link.UprobeOptions{Offset: offset},
		)
		if err != nil {
			log.Printf("Error setting the uprobe_wi: %v", err)
			return nil, err
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
			return nil, err
		}
		uprobe_ri, err := modelExecutable.Uprobe(
			simData.RTimingI.SymbolName,
			probeObjs.UprobeReadI,
			&link.UprobeOptions{Offset: offset},
		)
		if err != nil {
			log.Printf("Error setting the uprobe_ri: %v", err)
			return nil, err
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
			return nil, err
		}
		uprobe_ro, err := modelExecutable.Uprobe(
			simData.RTimingO.SymbolName,
			probeObjs.UprobeReadO,
			&link.UprobeOptions{Offset: offset},
		)
		if err != nil {
			log.Printf("Error setting the uprobe_ro: %v", err)
			return nil, err
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
		return nil, err
	}

	// wait for non-interactive simulations to terminate
	if simulationMode == my_types.Falsification {
		// wait until simulation terminates
		if err := binCmd.Wait(); err != nil {
			if err != nil && !cmdWasSigkilled(err) {
				log.Printf("Simulation finished with error: %s", err)
				return nil, err
			}
		} else {
			log.Print("Simulation completed successfully")
		}
	} else {
		// don't wait until it terminates
		log.Printf("Simulation is running...")
	}

	// collect or stream output trace
	if simulationMode == my_types.Monitoring || simulationMode == my_types.SignalPerturbation {
		// Create the Redis client
		redisClient := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
		// Get the simulation id
		simulationId := strconv.Itoa(0) // todo fix
		// Get the background context
		bg_ctx := context.Background()
		// Add a new Redis set fot the current run
		if err := redisClient.SAdd(bg_ctx, "simulation", simulationId).Err(); err != nil {
			log.Print("Failed to add simulation set to Redis:", err)
			return nil, errors.New("Error adding new simulation set to Redis")
		}
		// Create a ring buffer reader
		rbReader, err := ringbuf.NewReader(probeObjs.OutRb)
		if err != nil {
			log.Printf("Failed to create ring buffer reader: %v", err)
			return nil, errors.New("Error creating the ring buffer reader")
		}
		defer rbReader.Close()
		// Read events from the ring buffer and write them to Redis
		var records []my_types.OutRecord
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
				oRec := my_types.OutRecord{
					Time:   binary.LittleEndian.Uint32(raw),
					Values: _vals,
				}
				records = append(records, oRec)
			} else if writtenRecords+uint32(len(records)) == CYCLES {
				// Terminate
				break
			}
			if len(records) >= 50 {
				if err = writeToRedis(bg_ctx, redisClient, simulationKey, records); err != nil {
					return nil, errors.New("Error writing records to Redis")
				}
				// Empty local record slice
				writtenRecords += uint32(len(records))
				records = []my_types.OutRecord{}
			}
		}
		if len(records) != 0 {
			// Flush last records
			if err = writeToRedis(bg_ctx, redisClient, simulationKey, records); err != nil {
				return nil, errors.New("Error writing records to Redis")
			}
			// Empty local record slice
			writtenRecords += uint32(len(records))
			records = []my_types.OutRecord{}
		}
	} else if simulationMode == my_types.Falsification {
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
				return nil, err
			}
			defer innerTrace.Close()
			// trace extraction
			values := make([]float64, CYCLES)
			for pos := uint32(0); pos < CYCLES; pos++ {
				err := innerTrace.Lookup(&pos, &values[pos])
				if err != nil {
					log.Printf("Trace lookup failed: %s\n", err)
					return nil, err
				}
			}
			signTrace.Values = values
			outSignals.Signals = append(outSignals.Signals, signTrace)
			return &outSignals, nil
		}
	}

	// todo: support enforcement

	return nil, nil
}

// Writes a slice of records to Redis
func writeToRedis(ctx context.Context, redisClient *redis.Client, simulationKey string, records []my_types.OutRecord) error {

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
