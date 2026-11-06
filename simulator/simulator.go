package simulator

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/dariofad/river/my_types"
	"github.com/redis/go-redis/v9"
	"github.com/vmihailenco/msgpack/v5"
)

var VERBOSE bool
var BENCH bool
var RATIO uint32
var CYCLES uint32

const (
	redisSimulationSetKey = "simulation"
	redisSimulationID     = "0"
	redisSimulationKey    = "simulation:0"
	redisSignalsKey       = "simulation:0:signals"
	redisStatusKey        = "simulation:0:status"
)

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

func newRedisClient() *redis.Client {
	addr := os.Getenv("RIVER_REDIS_ADDR")
	if addr == "" {
		addr = "localhost:6379"
	}
	return redis.NewClient(&redis.Options{Addr: addr})
}

// ResetRedisSimulation clears previous simulation data, signals, and errors from
// Redis and records the initial "starting" status for the new simulation run.
func ResetRedisSimulation(ctx context.Context, mode my_types.Service) error {
	redisClient := newRedisClient()
	defer redisClient.Close()

	if err := redisClient.Del(ctx, redisSimulationSetKey, redisSimulationKey, redisSignalsKey, redisStatusKey).Err(); err != nil {
		log.Printf("Warning: could not clear previous simulation state in Redis: %v", err)
		return my_types.NewSimulationErrorf(my_types.ErrCategoryRedis, "clear Redis simulation state: %w", err)
	}
	return writeRedisStatus(ctx, redisClient, mode, my_types.StatusStarting, my_types.ErrCategoryNone, "Simulation is starting")
}

// UpdateRedisStatus writes the current simulation status or error to Redis.
func UpdateRedisStatus(ctx context.Context, mode my_types.Service, status my_types.ServerStatus, category my_types.ErrorCategory, message string) error {
	redisClient := newRedisClient()
	defer redisClient.Close()
	return writeRedisStatus(ctx, redisClient, mode, status, category, message)
}

func writeRedisStatus(ctx context.Context, redisClient *redis.Client, mode my_types.Service, status my_types.ServerStatus, category my_types.ErrorCategory, message string) error {
	payload, err := msgpack.Marshal(my_types.SimulationStatus{
		Status:    status,
		Mode:      mode.String(),
		Category:  category,
		Message:   message,
		Timestamp: time.Now().Unix(),
	})
	if err != nil {
		return my_types.NewSimulationErrorf(my_types.ErrCategoryRedis, "encode simulation status: %w", err)
	}
	if err := redisClient.Set(ctx, redisStatusKey, payload, 0).Err(); err != nil {
		log.Printf("Warning: failed to store simulation status in Redis: %v", err)
		return my_types.NewSimulationErrorf(my_types.ErrCategoryRedis, "store simulation status in Redis: %w", err)
	}
	return nil
}

func setCycles(spec *ebpf.CollectionSpec, config my_types.Configuration) error {

	// set ratio
	ratio, err := strconv.ParseUint(config.MinorToMajorRatio, 10, 64) // base 10
	if err != nil {
		log.Printf("Error converting MinorToMinorRatio: %s", err)
		return my_types.NewSimulationErrorf(my_types.ErrCategoryManifest, "invalid minor-to-major ratio %q: %w", config.MinorToMajorRatio, err)
	}
	RATIO = uint32(ratio)
	if err = spec.Variables["MINOR_TO_MAJOR_RATIO"].Set(RATIO); err != nil {
		log.Printf("Error setting MinorToMajorRation in spec: %s", err)
		return my_types.NewSimulationErrorf(my_types.ErrCategoryEBPF, "set MINOR_TO_MAJOR_RATIO in eBPF spec: %w", err)
	}
	log.Printf("Minor_to_major_ratio: %d", RATIO)

	// set cycles
	cycles, err := strconv.ParseUint(config.NofCycles, 10, 64) // base 10
	if err != nil {
		log.Printf("Error converting Cycles: %s", err)
		return my_types.NewSimulationErrorf(my_types.ErrCategoryManifest, "invalid cycle count %q: %w", config.NofCycles, err)
	}
	CYCLES = uint32(cycles)
	if err = spec.Variables["MAX_CYCLES"].Set(CYCLES); err != nil {
		log.Printf("Error setting Cycles in spec: %s", err)
		return my_types.NewSimulationErrorf(my_types.ErrCategoryEBPF, "set MAX_CYCLES in eBPF spec: %w", err)
	}
	log.Printf("Cycles: %d", CYCLES)

	return nil
}

func signalKey(signal my_types.Signal) string {
	if signal.Path != "" {
		return signal.Path
	}
	return signal.Name
}

func lookupTrajectoryValues(rawTrajectory map[string]interface{}, signal my_types.Signal) ([]interface{}, bool) {
	if signal.Path != "" {
		if vals, ok := rawTrajectory[signal.Path].([]interface{}); ok {
			return vals, true
		}
	}
	if signal.Name != "" {
		if vals, ok := rawTrajectory[signal.Name].([]interface{}); ok {
			return vals, true
		}
	}
	return nil, false
}

func matchWritableSignal(key string, cWrites []my_types.Signal) (my_types.Signal, bool) {
	for _, configured := range cWrites {
		if (configured.Path != "" && configured.Path == key) || configured.Name == key {
			return configured, true
		}
	}
	return my_types.Signal{}, false
}

// Converts raw simulation data to a proper trajectory
func extractTrajectory(rawTrajectory map[string]interface{}, config my_types.Configuration) (map[string][]uint64, error) {

	trajectory := make(map[string][]uint64)
	// todo: multiple writes on the same signal can lead to a wrong trajectory
	for _, group := range config.Writes {
		for _, signal := range group.Signals {
			key := signalKey(signal)
			vals := make([]uint64, CYCLES)
			if signalTrajectory, ok := lookupTrajectoryValues(rawTrajectory, signal); ok {
				if len(signalTrajectory) != int(CYCLES) {
					return nil, my_types.NewSimulationErrorf(my_types.ErrCategoryTrajectory, "trajectory for %s has %d values; expected %d", key, len(signalTrajectory), CYCLES)
				}
				for t, rawVal := range signalTrajectory {
					val, err := my_types.EncodeSignalValue(rawVal, signal.Type)
					if err != nil {
						log.Printf("Cannot convert trajectory value %v for %s: %v", rawVal, key, err)
						return nil, my_types.NewSimulationErrorf(my_types.ErrCategoryTrajectory, "convert trajectory value for %s: %w", key, err)
					}
					vals[t] = val
				}
			} else {
				log.Printf("Cannot extract raw trajectory for signal %s", key)
				return nil, my_types.NewSimulationErrorf(my_types.ErrCategoryTrajectory, "missing trajectory for writable signal %q", key)
			}
			trajectory[key] = vals
		}
	}
	return trajectory, nil
}

func collectConfiguredSignals(config *my_types.Configuration) ([]my_types.Signal, []my_types.Signal, uint32, uint32) {
	var cReads []my_types.Signal
	var cWrites []my_types.Signal
	var nofReads uint32
	var nofWrites uint32
	for _, group := range config.Reads {
		cReads = append(cReads, group.Signals...)
		nofReads += uint32(len(group.Signals))
	}
	for _, group := range config.Writes {
		cWrites = append(cWrites, group.Signals...)
		nofWrites += uint32(len(group.Signals))
	}
	return cReads, cWrites, nofReads, nofWrites
}

func setupInnerTrajectoryMaps(
	spec *ebpf.CollectionSpec,
	probeObjs *probeObjects,
	cReads []my_types.Signal,
	cWrites []my_types.Signal,
	trajectory map[string][]uint64,
) (func(), error) {
	trajectoryMapSpec := spec.Maps["trajectory_map"]
	trajectoryMap := probeObjs.TrajectoryMap
	nofReads := len(cReads)
	totalSignals := nofReads + len(cWrites)

	innerMapKeys := make([]uint32, CYCLES)
	for p := range innerMapKeys {
		innerMapKeys[p] = uint32(p)
	}

	var cleanups []func()
	cleanupAll := func() {
		for i := len(cleanups) - 1; i >= 0; i-- {
			cleanups[i]()
		}
	}

	for s := 0; s < totalSignals; s++ {
		innerSpec := trajectoryMapSpec.InnerMap.Copy()
		innerSpec.MaxEntries = paddedEntries(CYCLES)
		inner, err := ebpf.NewMap(innerSpec)
		if err != nil {
			log.Printf("Cannot create sequence (inner) map: %s", err)
			cleanupAll()
			return nil, my_types.NewSimulationErrorf(my_types.ErrCategoryEBPF, "create inner sequence map for signal %d: %w", s, err)
		}
		pinPath := "/sys/fs/bpf/sequence_values_" + strconv.FormatInt(int64(s), 10)
		_ = os.Remove(pinPath)
		if err := inner.Pin(pinPath); err != nil {
			log.Printf("Cannot pin inner map at %v", pinPath)
			inner.Close()
			cleanupAll()
			return nil, my_types.NewSimulationErrorf(my_types.ErrCategoryEBPF, "pin inner map at %s: %w", pinPath, err)
		}
		cleanups = append(cleanups, func() {
			if err := inner.Unpin(); err != nil {
				log.Printf("Cannot unpin inner map, err: %v", err)
			}
			log.Printf("Map unpinned from %s", pinPath)
			inner.Close()
		})

		if s >= nofReads {
			sw := s - nofReads
			sKey := signalKey(cWrites[sw])
			log.Printf("sName: %v", sKey)
			_, err = inner.BatchUpdate(innerMapKeys, trajectory[sKey], &ebpf.BatchOptions{
				Flags: uint64(ebpf.UpdateAny),
			})
			if err != nil {
				log.Printf("Injection of trajectory failed, %v", err)
				cleanupAll()
				return nil, my_types.NewSimulationErrorf(my_types.ErrCategoryTrajectory, "inject trajectory for %s: %w", sKey, err)
			}
			log.Printf("Input trajectory %d successfully injected", s)
		}

		key := uint32(s)
		value := uint32(inner.FD())
		if err := trajectoryMap.Update(key, value, 0); err != nil {
			if errno, ok := err.(syscall.Errno); ok {
				log.Printf("KERNEL ERROR: errno=%d", errno)
			} else {
				log.Printf("ERROR: %v", err)
			}
			log.Printf("Failed to insert FD for signal %d: %s", s, err)
			cleanupAll()
			return nil, my_types.NewSimulationErrorf(my_types.ErrCategoryEBPF, "insert inner map FD for signal %d: %w", s, err)
		}
	}

	return cleanupAll, nil
}

func attachGroupProbes(
	modelExecutable *link.Executable,
	groups []my_types.Group,
	prog *ebpf.Program,
	targetPID int,
	startGroupBase int,
	kind string,
) ([]link.Link, int, error) {
	var links []link.Link
	closeLinks := func() {
		for _, l := range links {
			l.Close()
		}
	}

	groupBase := startGroupBase
	for _, group := range groups {
		cookie := uprobeCookie(groupBase, len(group.Signals))
		log.Printf("%s group %d, %d signals, cookie: %d", kind, groupBase, len(group.Signals), cookie)
		offset, err := strconv.ParseUint(group.Offset, 0, 64)
		if err != nil {
			closeLinks()
			log.Printf("Error converting uprobe offset: %s", err)
			return nil, groupBase, my_types.NewSimulationErrorf(my_types.ErrCategoryManifest, "parse %s uprobe offset %q: %w", kind, group.Offset, err)
		}
		options := &link.UprobeOptions{Offset: offset, Cookie: cookie, PID: targetPID}
		var uprobeLink link.Link
		if group.Retprobe {
			uprobeLink, err = modelExecutable.Uretprobe(group.Symbol, prog, options)
		} else {
			uprobeLink, err = modelExecutable.Uprobe(group.Symbol, prog, options)
		}
		if err != nil {
			closeLinks()
			log.Printf("Error setting the %s probe: %v", kind, err)
			return nil, groupBase, my_types.NewSimulationErrorf(my_types.ErrCategoryEBPF, "attach %s probe on symbol %q: %w", kind, group.Symbol, err)
		}
		log.Printf("%s probe linked", kind)
		links = append(links, uprobeLink)
		groupBase += len(group.Signals)
	}
	return links, groupBase, nil
}

func Start(
	simulationMode my_types.Service,
	config *my_types.Configuration,
	rawTrajectory map[string]interface{},
	readyCh chan<- struct{},
	errCh chan error,
	resCh chan my_types.OutputTrace,
	pertCh <-chan map[string]interface{},
	statePertCh <-chan []my_types.StateRecord,
	wg *sync.WaitGroup,
) {
	defer wg.Done()

	var readyOnce sync.Once
	signalReady := func() {
		if readyCh != nil {
			readyOnce.Do(func() {
				close(readyCh)
			})
		}
	}

	// Load eBPF collection spec
	spec, err := loadProbe()
	if err != nil {
		log.Printf("loading collectionSpec: %s", err)
		errCh <- my_types.NewSimulationErrorf(my_types.ErrCategoryEBPF, "cannot retrieve eBPF collection spec: %w", err)
		return
	}

	// Configuration addresses are static ELF virtual addresses. Validate them
	// before starting the model; they will be translated while the child is
	// stopped immediately after exec.
	relocation, err := configureRelocation(*config)
	if err != nil {
		log.Printf("Cannot configure ASLR-safe target addresses: %v", err)
		errCh <- my_types.NewSimulationError(my_types.ErrCategoryTarget, err)
		return
	}

	// Set cycles in ebpf
	if err = setCycles(spec, *config); err != nil {
		errCh <- err
		return
	}

	// Set max entries in eBPF spec, retrieve signals, write desired trajectories
	cReads, cWrites, nof_signals_read, nof_signals_written := collectConfiguredSignals(config)

	log.Printf("nof_signals_read %d, nof_signals_written %d", nof_signals_read, nof_signals_written)
	if err = spec.Variables["NOF_SIGNALS_READ"].Set(nof_signals_read); err != nil {
		log.Printf("Error setting variable NOF_SIGNALS_READ: %v", err)
		errCh <- my_types.NewSimulationErrorf(my_types.ErrCategoryEBPF, "set NOF_SIGNALS_READ: %w", err)
		return
	}
	if err = spec.Variables["NOF_SIGNALS_WRITTEN"].Set(nof_signals_written); err != nil {
		log.Printf("Error setting variable NOF_SIGNALS_WRITTEN: %v", err)
		errCh <- my_types.NewSimulationErrorf(my_types.ErrCategoryEBPF, "set NOF_SIGNALS_WRITTEN: %w", err)
		return
	}

	// Map specifications must be finalized before LoadAndAssign: that call
	// creates the kernel maps, and changing a spec afterwards cannot resize an
	// existing map.
	if err := configureSignalMapSizes(spec, nof_signals_read+nof_signals_written); err != nil {
		log.Printf("Cannot configure signal map sizes: %v", err)
		errCh <- my_types.NewSimulationError(my_types.ErrCategoryEBPF, err)
		return
	}

	// Extract trajectory before creating kernel maps so invalid trajectories fail fast
	trajectory, err := extractTrajectory(rawTrajectory, *config)
	if err != nil {
		errCh <- err
		return
	}
	log.Print("Input trajectory extracted successfully")

	// create the probeObjects and load eBPF objects (maps + programs) into the kernel
	probeObjs := probeObjects{}
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
		errCh <- my_types.NewSimulationErrorf(my_types.ErrCategoryEBPF, "load eBPF objects into kernel: %w", err)
		return
	}
	defer probeObjs.Close()

	// Associate every eBPF signal slot with its native scalar type. Read slots
	// precede write slots, matching the address and trajectory map layout.
	for index, signal := range append(append([]my_types.Signal{}, cReads...), cWrites...) {
		info, typeErr := my_types.ParseSignalType(signal.Type)
		if typeErr != nil {
			errCh <- my_types.NewSimulationErrorf(my_types.ErrCategoryManifest, "signal %q: %w", signal.Name, typeErr)
			return
		}
		if typeErr = probeObjs.SignalTypeMap.Update(uint32(index), uint32(info.Code), 0); typeErr != nil {
			errCh <- my_types.NewSimulationErrorf(my_types.ErrCategoryEBPF, "set type for signal %q: %w", signal.Name, typeErr)
			return
		}
	}

	cleanupInnerMaps, err := setupInnerTrajectoryMaps(spec, &probeObjs, cReads, cWrites, trajectory)
	if err != nil {
		errCh <- err
		return
	}
	defer cleanupInnerMaps()

	// Pin perturbation ring buffers prior to signalling readiness so immediate
	// perturbation injections cannot race with buffer pinning.
	switch simulationMode {
	case my_types.StatePerturbation:
		pertRBPath := "/sys/fs/bpf/state_pertbuf"
		_ = os.Remove(pertRBPath)
		if err := probeObjs.StateRb.Pin(pertRBPath); err != nil {
			log.Printf("Cannot pin state perturbation buffer at %v", pertRBPath)
			errCh <- my_types.NewSimulationErrorf(my_types.ErrCategoryEBPF, "pin state perturbation ring buffer at %s: %w", pertRBPath, err)
			return
		}
		defer func() {
			if err := probeObjs.StateRb.Unpin(); err != nil {
				log.Printf("Cannot unpin state perturbation buffer: %v", err)
			}
		}()
	case my_types.SignalPerturbation:
		pertRBPath := "/sys/fs/bpf/pertbuf"
		_ = os.Remove(pertRBPath)
		if err := probeObjs.InjRb.Pin(pertRBPath); err != nil {
			log.Printf("Cannot pin perturbation buffer at %v", pertRBPath)
			errCh <- my_types.NewSimulationErrorf(my_types.ErrCategoryEBPF, "pin signal perturbation ring buffer at %s: %w", pertRBPath, err)
			return
		}
		defer func() {
			if err := probeObjs.InjRb.Unpin(); err != nil {
				log.Printf("Cannot unpin perturbation buffer: %v", err)
			}
		}()
	}

	modelExecutable, err := link.OpenExecutable(config.ModelPath)
	if err != nil {
		log.Printf("Error opening model executable: %s", err)
		errCh <- my_types.NewSimulationErrorf(my_types.ErrCategoryTarget, "open model executable %q: %w", config.ModelPath, err)
		return
	}

	// Start preparing the simulation commands
	ctx, cancelSimulation := context.WithCancel(context.Background())
	defer cancelSimulation()
	binCmd := exec.CommandContext(ctx, config.ModelPath)
	if VERBOSE {
		binCmd.Stdout = os.Stdout
	}
	binCmd.Stderr = os.Stderr
	// Start the child under ptrace. Linux stops it immediately after exec, so
	// its ASLR mapping is visible before any model instruction can run.
	log.Print("Starting simulation")
	runtime.LockOSThread()
	ptraceThreadLocked := true
	defer func() {
		if ptraceThreadLocked {
			runtime.UnlockOSThread()
		}
	}()
	if err := startStopped(binCmd); err != nil {
		log.Printf("Failed to start simulation command: %s", err)
		errCh <- my_types.NewSimulationErrorf(my_types.ErrCategoryTarget, "start target binary %q: %w", config.ModelPath, err)
		return
	}
	runtimeAddresses, loadBias, err := relocation.runtimeAddresses(binCmd.Process.Pid)
	if err != nil {
		_ = abortStopped(binCmd)
		log.Printf("Cannot resolve target runtime addresses: %s", err)
		errCh <- my_types.NewSimulationErrorf(my_types.ErrCategoryTarget, "resolve target runtime addresses: %w", err)
		return
	}
	for p, runtimeAddress := range runtimeAddresses {
		if err = probeObjs.AddressMap.Update(uint32(p), runtimeAddress, 0); err != nil {
			_ = abortStopped(binCmd)
			log.Printf("Cannot update runtime address for signal %d: %v", p, err)
			errCh <- my_types.NewSimulationErrorf(my_types.ErrCategoryEBPF, "update runtime address for signal %d: %w", p, err)
			return
		}
	}

	// Attach the uprobes only to this target while it is still stopped.
	targetPID := binCmd.Process.Pid
	var groupBase int
	if nof_signals_read > 0 {
		readLinks, nextBase, attachErr := attachGroupProbes(modelExecutable, config.Reads, probeObjs.UprobeRead, targetPID, groupBase, "Read")
		if attachErr != nil {
			_ = abortStopped(binCmd)
			errCh <- attachErr
			return
		}
		for _, l := range readLinks {
			defer l.Close()
		}
		groupBase = nextBase
	}
	if nof_signals_written > 0 {
		writeLinks, _, attachErr := attachGroupProbes(modelExecutable, config.Writes, probeObjs.UprobeWrite, targetPID, groupBase, "Write")
		if attachErr != nil {
			_ = abortStopped(binCmd)
			errCh <- attachErr
			return
		}
		for _, l := range writeLinks {
			defer l.Close()
		}
	}

	uprobe_timer, err := modelExecutable.Uprobe(
		config.TimerSymbol,
		probeObjs.UprobeTimer,
		&link.UprobeOptions{PID: targetPID},
	)
	if err != nil {
		_ = abortStopped(binCmd)
		log.Printf("Error setting the uprobe_timer: %v", err)
		errCh <- my_types.NewSimulationErrorf(my_types.ErrCategoryEBPF, "attach timer uprobe on %q: %w", config.TimerSymbol, err)
		return
	}
	defer uprobe_timer.Close()

	detachErr := detachStopped(binCmd)
	ptraceThreadLocked = false
	runtime.UnlockOSThread()
	if detachErr != nil {
		_ = abortStopped(binCmd)
		log.Printf("Cannot detach from target after address setup: %s", detachErr)
		errCh <- my_types.NewSimulationErrorf(my_types.ErrCategoryTarget, "detach target process: %w", detachErr)
		return
	}

	// Notify the server that all probes are attached and the target is running.
	signalReady()

	// Start measuring only once the untraced model can execute.
	simulationStartTime := time.Now()
	defer func() {
		stopSimulator(simulationStartTime, nof_signals_read, nof_signals_written, *config)
	}()

	// wait for non-interactive simulations to terminate
	if simulationMode == my_types.Falsification {
		if err := binCmd.Wait(); err != nil {
			if !cmdWasSigkilled(err) {
				log.Printf("Simulation finished with error: %s", err)
				errCh <- my_types.NewSimulationErrorf(my_types.ErrCategoryTarget, "target process exited with error: %w", err)
				return
			}
		} else {
			log.Print("Simulation completed successfully")
		}
	} else {
		log.Printf("Simulation is running...")
	}

	var simulationDone <-chan error
	if simulationMode != my_types.Falsification {
		done := make(chan error, 1)
		simulationDone = done
		go func() {
			waitErr := binCmd.Wait()
			if cmdWasSigkilled(waitErr) {
				waitErr = nil
			}
			done <- waitErr
			close(done)
		}()
	}

	switch simulationMode {
	case my_types.Monitoring:
		if err := monitorSimulation(context.Background(), probeObjs, nof_signals_read, cReads, simulationDone, cancelSimulation); err != nil {
			errCh <- err
			return
		}
	case my_types.Falsification:
		outSignals, err := collectFalsificationTrace(cReads)
		if err != nil {
			errCh <- err
			return
		}
		resCh <- outSignals
	case my_types.StatePerturbation:
		if err := runStatePerturbation(context.Background(), cancelSimulation, statePertCh, probeObjs, relocation, loadBias, nof_signals_read, cReads, simulationDone); err != nil {
			errCh <- err
			return
		}
	case my_types.SignalPerturbation:
		if err := runSignalPerturbation(context.Background(), cancelSimulation, pertCh, probeObjs, nof_signals_read, nof_signals_written, cReads, cWrites, simulationDone); err != nil {
			errCh <- err
			return
		}
	}
}

func collectFalsificationTrace(cReads []my_types.Signal) (my_types.OutputTrace, error) {
	var outSignals my_types.OutputTrace
	for id, signal := range cReads {
		var signTrace my_types.Trace
		signTrace.SignName = signal.Name
		signTrace.Type = signal.Type
		signalKey := uint32(id)
		pinPath := "/sys/fs/bpf/sequence_values_" + strconv.FormatInt(int64(signalKey), 10)
		innerTrace, err := ebpf.LoadPinnedMap(pinPath, nil)
		if err != nil {
			log.Printf("Cannot recover inner pinned map at %s: %v", pinPath, err)
			return outSignals, my_types.NewSimulationErrorf(my_types.ErrCategoryEBPF, "load pinned trace map at %s: %w", pinPath, err)
		}
		defer innerTrace.Close()

		values := make([]any, CYCLES)
		for pos := uint32(0); pos < CYCLES; pos++ {
			var bits uint64
			err := innerTrace.Lookup(&pos, &bits)
			if err != nil {
				log.Printf("Trace lookup failed: %s\n", err)
				return outSignals, my_types.NewSimulationErrorf(my_types.ErrCategoryEBPF, "lookup trace sample %d for %s: %w", pos, signal.Name, err)
			}
			value, decodeErr := my_types.DecodeSignalValue(bits, signal.Type)
			if decodeErr != nil {
				return outSignals, my_types.NewSimulationErrorf(my_types.ErrCategoryTrajectory, "decode trace value for %s: %w", signal.Name, decodeErr)
			}
			values[pos] = value
		}
		signTrace.Values = values
		outSignals.Signals = append(outSignals.Signals, signTrace)
	}
	return outSignals, nil
}

func runStatePerturbation(
	parentCtx context.Context,
	cancelSimulation context.CancelFunc,
	statePertCh <-chan []my_types.StateRecord,
	probeObjs probeObjects,
	relocation *relocationConfig,
	loadBias uint64,
	nofSignalsRead uint32,
	cReads []my_types.Signal,
	simulationDone <-chan error,
) error {
	ctx, cancel := context.WithCancel(parentCtx)
	defer cancel()

	errChm := make(chan error, 1)
	errChi := make(chan error, 1)

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case perturbation, ok := <-statePertCh:
				if !ok {
					return
				}
				if err := injectStatePerturbationBatch(perturbation, relocation, loadBias); err != nil {
					log.Printf("State perturbation injection failed: %v", err)
					select {
					case errChi <- err:
					default:
					}
					cancelSimulation()
					return
				}
			}
		}
	}()

	go func() {
		errChm <- monitorSimulation(ctx, probeObjs, nofSignalsRead, cReads, simulationDone, cancelSimulation)
	}()

	monitorErr := <-errChm
	select {
	case injErr := <-errChi:
		return injErr
	default:
		return monitorErr
	}
}

func injectStatePerturbationBatch(perturbation []my_types.StateRecord, relocation *relocationConfig, loadBias uint64) error {
	tempFile, err := os.CreateTemp("", "model_state_records_*.bin")
	if err != nil {
		return my_types.NewSimulationErrorf(my_types.ErrCategoryPerturbation, "create temporary state perturbation file: %w", err)
	}
	tempPath := tempFile.Name()
	defer os.Remove(tempPath)
	defer tempFile.Close()

	for _, r := range perturbation {
		info, valueErr := my_types.ParseSignalType(r.Type)
		if valueErr != nil || r.ValueSize != info.Size {
			return my_types.NewSimulationErrorf(my_types.ErrCategoryPerturbation, "invalid state perturbation type/size for %#x", r.Addr)
		}
		if err := relocation.image.validateDataRange(r.Addr, uint64(r.ValueSize), true); err != nil {
			return my_types.NewSimulationErrorf(my_types.ErrCategoryPerturbation, "invalid state perturbation address range: %w", err)
		}
		runtimeAddress, ok := addUint64(r.Addr, loadBias)
		if !ok {
			return my_types.NewSimulationErrorf(my_types.ErrCategoryPerturbation, "state perturbation address %#x overflows after relocation", r.Addr)
		}
		bits, valueErr := my_types.EncodeSignalValue(r.Value, r.Type)
		if valueErr != nil {
			return my_types.NewSimulationErrorf(my_types.ErrCategoryPerturbation, "invalid state perturbation value: %w", valueErr)
		}
		_ = binary.Write(tempFile, binary.LittleEndian, r.Time)
		_ = binary.Write(tempFile, binary.LittleEndian, r.ValueSize)
		_ = binary.Write(tempFile, binary.LittleEndian, runtimeAddress)
		_ = binary.Write(tempFile, binary.LittleEndian, bits)
	}
	if err := tempFile.Close(); err != nil {
		return my_types.NewSimulationErrorf(my_types.ErrCategoryPerturbation, "flush temporary state perturbation file: %w", err)
	}

	enableInjectorVerbosity := "0"
	if VERBOSE {
		enableInjectorVerbosity = "1"
	}
	injCmd := exec.Command(
		"sudo",
		"./simulator/state_injector",
		tempPath,
		enableInjectorVerbosity,
	)
	injCmd.Stdout = os.Stdout
	injCmd.Stderr = os.Stderr
	if err = injCmd.Run(); err != nil {
		return my_types.NewSimulationErrorf(my_types.ErrCategoryPerturbation, "state_injector command failed: %w", err)
	}
	return nil
}

func runSignalPerturbation(
	parentCtx context.Context,
	cancelSimulation context.CancelFunc,
	pertCh <-chan map[string]interface{},
	probeObjs probeObjects,
	nofSignalsRead uint32,
	nofSignalsWritten uint32,
	cReads []my_types.Signal,
	cWrites []my_types.Signal,
	simulationDone <-chan error,
) error {
	ctx, cancel := context.WithCancel(parentCtx)
	defer cancel()

	errChm := make(chan error, 1)
	errChi := make(chan error, 1)

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case perturbation, ok := <-pertCh:
				if !ok {
					return
				}
				if err := injectSignalPerturbationBatch(perturbation, nofSignalsWritten, cWrites); err != nil {
					log.Printf("Signal perturbation injection failed: %v", err)
					select {
					case errChi <- err:
					default:
					}
					cancelSimulation()
					return
				}
			}
		}
	}()

	go func() {
		errChm <- monitorSimulation(ctx, probeObjs, nofSignalsRead, cReads, simulationDone, cancelSimulation)
	}()

	monitorErr := <-errChm
	select {
	case injErr := <-errChi:
		return injErr
	default:
		return monitorErr
	}
}

func injectSignalPerturbationBatch(perturbation map[string]interface{}, nofSignalsWritten uint32, cWrites []my_types.Signal) error {
	pertRecords, err := extractPerturbationRecords(perturbation, nofSignalsWritten, cWrites)
	if err != nil {
		return my_types.NewSimulationError(my_types.ErrCategoryPerturbation, err)
	}
	tempFile, err := os.CreateTemp("", "model_records_*.bin")
	if err != nil {
		return my_types.NewSimulationErrorf(my_types.ErrCategoryPerturbation, "create temporary signal perturbation file: %w", err)
	}
	tempPath := tempFile.Name()
	defer os.Remove(tempPath)
	defer tempFile.Close()

	for _, r := range pertRecords {
		_ = binary.Write(tempFile, binary.LittleEndian, r.Time)
		_ = binary.Write(tempFile, binary.LittleEndian, r.Filler)
		for _, v := range r.Values {
			_ = binary.Write(tempFile, binary.LittleEndian, v)
		}
	}
	if err := tempFile.Close(); err != nil {
		return my_types.NewSimulationErrorf(my_types.ErrCategoryPerturbation, "flush temporary signal perturbation file: %w", err)
	}

	enableInjectorVerbosity := "0"
	if VERBOSE {
		enableInjectorVerbosity = "1"
	}
	injCmd := exec.Command(
		"sudo",
		"./simulator/injector",
		strconv.FormatInt(int64(nofSignalsWritten), 10),
		tempPath,
		enableInjectorVerbosity,
	)
	injCmd.Stdout = os.Stdout
	injCmd.Stderr = os.Stderr
	if err = injCmd.Run(); err != nil {
		return my_types.NewSimulationErrorf(my_types.ErrCategoryPerturbation, "injector command failed: %w", err)
	}
	return nil
}

func stopSimulator(simulationStartTime time.Time, nof_signals_read, nof_signals_written uint32, config my_types.Configuration) {

	elapsedTime := time.Since(simulationStartTime)
	statsFName := "_stats.csv"
	file, err := os.OpenFile(statsFName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	logLine := config.ModelPath + "," +
		config.NofCycles + "," +
		config.MinorToMajorRatio + "," +
		strconv.FormatUint(uint64(nof_signals_read), 10) + "," +
		strconv.FormatUint(uint64(nof_signals_written), 10) + "," +
		strconv.FormatInt(elapsedTime.Nanoseconds(), 10) + "\n"

	if _, err := file.WriteString(logLine); err != nil {
		log.Printf("Error writing stats line: %s", err)
	}

	if BENCH {
		var line string
		log.Print("Press <enter> to stop the simulation and unload the maps")
		fmt.Scanln(&line)
	} else {
		log.Print("Simulator exited")
	}
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

func extractPerturbationRecords(data map[string]interface{}, nof_signals_written uint32, cWrites []my_types.Signal) ([]my_types.ModelRecord, error) {

	// extract time
	timeVals := make([]uint32, 0)
	if rawTime, ok := data["time"].([]interface{}); ok {
		for _, rawVal := range rawTime {
			var val uint32
			val, ok := customConversion(rawVal)
			if !ok {
				return nil, errors.New("cannot convert perturbation time value to integer")
			}
			timeVals = append(timeVals, val)
		}
	} else {
		log.Print("Cannot extract raw values for time")
		return nil, errors.New("perturbation extraction error: missing time array")
	}
	signalVals := make(map[string][]uint64)
	// extract signals
	for signal := range data {
		if signal == "time" {
			continue
		}
		vals := make([]uint64, 0)
		if rawSignal, ok := data[signal].([]interface{}); ok {
			configured, matched := matchWritableSignal(signal, cWrites)
			if !matched {
				return nil, fmt.Errorf("unknown writable signal %q", signal)
			}
			for _, rawVal := range rawSignal {
				val, err := my_types.EncodeSignalValue(rawVal, configured.Type)
				if err != nil {
					return nil, fmt.Errorf("convert perturbation value for %s: %w", signal, err)
				}
				vals = append(vals, val)
			}
			if len(vals) != len(timeVals) {
				return nil, fmt.Errorf("perturbation %q has %d values for %d time values", signal, len(vals), len(timeVals))
			}
			signalVals[signalKey(configured)] = vals
		} else {
			log.Printf("Cannot extract raw values for %v", signal)
			return nil, fmt.Errorf("perturbation %q values must be an array", signal)
		}
	}
	// pack into model records and return
	pertRecords := make([]my_types.ModelRecord, 0)
	for p, v := range timeVals {
		var record my_types.ModelRecord
		record.Time = v
		record.Filler = 0
		record.Values = make([]uint64, nof_signals_written)
		for signal_pos, signal := range cWrites {
			if vals, ok := signalVals[signalKey(signal)]; ok {
				record.Values[signal_pos] = vals[p]
			} else {
				// append zero
				record.Values[signal_pos] = 0
			}
		}
		pertRecords = append(pertRecords, record)
	}
	return pertRecords, nil
}

func monitorSimulation(ctx context.Context, probeObjs probeObjects, nof_signals_read uint32, signals []my_types.Signal, simulationDone <-chan error, stopSimulation context.CancelFunc) error {

	// Create the Redis client
	redisClient := newRedisClient()
	defer redisClient.Close()
	// Add a new Redis set for the current run
	if err := redisClient.SAdd(ctx, redisSimulationSetKey, redisSimulationID).Err(); err != nil {
		log.Print("Failed to add simulation set to Redis:", err)
		return my_types.NewSimulationErrorf(my_types.ErrCategoryRedis, "add simulation set to Redis: %w", err)
	}
	signalNames := make([]string, len(signals))
	for i, sig := range signals {
		signalNames[i] = sig.Name
	}
	signalsPayload, err := msgpack.Marshal(signalNames)
	if err != nil {
		return my_types.NewSimulationErrorf(my_types.ErrCategoryRedis, "encode simulation signal names: %w", err)
	}
	if err := redisClient.Set(ctx, redisSignalsKey, signalsPayload, 0).Err(); err != nil {
		log.Print("Failed to store simulation signal names in Redis:", err)
		return my_types.NewSimulationErrorf(my_types.ErrCategoryRedis, "store simulation signal names in Redis: %w", err)
	}
	// Create a ring buffer reader
	rbReader, err := ringbuf.NewReader(probeObjs.OutRb)
	if err != nil {
		log.Printf("Failed to create ring buffer reader: %v", err)
		return my_types.NewSimulationErrorf(my_types.ErrCategoryEBPF, "create ring buffer reader: %w", err)
	}
	defer rbReader.Close()
	// Read events from the ring buffer and write them to Redis
	var records []my_types.ModelRecord
	var writtenRecords uint32 = 0
	var completionErr error
	lastFlush := time.Now()

monitorLoop:
	for {
		rbReader.SetDeadline(time.Now().Add(50 * time.Millisecond))
		record, err := rbReader.Read()
		if err == nil {

			// check record validity
			raw := record.RawSample
			if len(raw) < int((nof_signals_read+1)*8) {
				log.Printf("Corrupted record: truncated to %d bytes", len(raw))
			}
			// convert to a structured record
			_vals := make([]uint64, nof_signals_read)
			for p := range _vals {
				_vals[p] = binary.LittleEndian.Uint64(raw[8+p*8 : 16+p*8])
			}
			oRec := my_types.ModelRecord{
				Time:   binary.LittleEndian.Uint32(raw),
				Values: _vals,
			}
			records = append(records, oRec)
			if CYCLES > 0 && oRec.Time >= CYCLES-1 {
				// The expected final cycle reached userspace. Ensure the model exits
				// even if bpf_send_signal() failed in the probe.
				stopSimulation()
			}
		} else {
			if !errors.Is(err, os.ErrDeadlineExceeded) {
				return my_types.NewSimulationErrorf(my_types.ErrCategoryEBPF, "read simulation ring buffer: %w", err)
			}
			receivedRecords := writtenRecords + uint32(len(records))
			if receivedRecords >= CYCLES {
				break
			}
			select {
			case waitErr := <-simulationDone:
				if waitErr != nil {
					completionErr = my_types.NewSimulationErrorf(my_types.ErrCategoryTarget, "simulation exited before monitoring completed: %w", waitErr)
				} else {
					completionErr = my_types.NewSimulationErrorf(my_types.ErrCategoryTarget, "simulation produced %d of %d expected records", receivedRecords, CYCLES)
				}
				break monitorLoop
			default:
			}
		}
		shouldFlush := len(records) >= 50 || (len(records) > 0 && (errors.Is(err, os.ErrDeadlineExceeded) || time.Since(lastFlush) >= 50*time.Millisecond))
		if shouldFlush {
			if err = writeToRedis(ctx, redisClient, redisSimulationKey, records, signals); err != nil {
				return my_types.NewSimulationErrorf(my_types.ErrCategoryRedis, "write records to Redis: %w", err)
			}
			// Empty local record slice
			writtenRecords += uint32(len(records))
			records = []my_types.ModelRecord{}
			lastFlush = time.Now()
		}
	}
	if len(records) != 0 {
		// Flush last records
		if err = writeToRedis(ctx, redisClient, redisSimulationKey, records, signals); err != nil {
			return my_types.NewSimulationErrorf(my_types.ErrCategoryRedis, "write records to Redis: %w", err)
		}
		// Empty local record slice
		writtenRecords += uint32(len(records))
		records = []my_types.ModelRecord{}
	}

	return completionErr
}

// Writes a slice of records to Redis
func writeToRedis(ctx context.Context, redisClient *redis.Client, simulationKey string, records []my_types.ModelRecord, signals []my_types.Signal) error {

	// convert records to string representation and add them to a Redis sorted set
	var z []redis.Z
	for _, rec := range records {
		values := make([]any, len(rec.Values))
		for i, bits := range rec.Values {
			if i >= len(signals) {
				return fmt.Errorf("record has more values than configured signals")
			}
			value, err := my_types.DecodeSignalValue(bits, signals[i].Type)
			if err != nil {
				return err
			}
			values[i] = value
		}
		payload, err := msgpack.Marshal(struct {
			Time   uint32 `msgpack:"TIME"`
			Values []any  `msgpack:"VALUES"`
		}{rec.Time, values})
		if err != nil {
			return err
		}
		z = append(z, redis.Z{Score: float64(rec.Time), Member: payload})
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
