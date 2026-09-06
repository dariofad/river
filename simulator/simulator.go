package simulator

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
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
)

var VERBOSE bool
var BENCH bool
var RATIO uint32
var CYCLES uint32

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

func setCycles(spec *ebpf.CollectionSpec, config my_types.Configuration) error {

	// set ratio
	ratio, err := strconv.ParseUint(config.MinorToMajorRatio, 10, 64) // base 10
	if err != nil {
		log.Printf("Error converting MinorToMinorRatio: %s", err)
		return err
	}
	RATIO = uint32(ratio)
	if err = spec.Variables["MINOR_TO_MAJOR_RATIO"].Set(RATIO); err != nil {
		log.Printf("Error setting MinorToMajorRation in spec: %s", err)
		return err
	}
	log.Printf("Minor_to_major_ratio: %d", RATIO)

	// set cycles
	cycles, err := strconv.ParseUint(config.NofCycles, 10, 64) // base 10
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
func extractTrajectory(rawTrajectory map[string]interface{}, config my_types.Configuration) (map[string][]float64, error) {

	trajectory := make(map[string][]float64)
	// todo: multiple writes on the same signal can lead to a wrong trajectory
	for _, group := range config.Writes {
		for _, signal := range group.Signals {
			vals := make([]float64, CYCLES)
			if rawTrajectory, ok := rawTrajectory[signal.Name].([]interface{}); ok {
				for t, rawVal := range rawTrajectory {
					val, ok := rawVal.(float64)
					if !ok {
						log.Printf("Cannot convert to float trajectory value %v", rawVal)
						return nil, errors.New("Cannot convert trajectory value to float64")
					}
					vals[t] = val
				}
			} else {
				log.Printf("Cannot extract raw trajectory for signal %s", signal.Name)
				return nil, errors.New("Trajectory extraction error")
			}
			trajectory[signal.Name] = vals
		}
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
	var config my_types.Configuration
	err = json.Unmarshal(rawSimData, &config)
	if err != nil {
		log.Printf("Error parsing the configuration: %s", err)
		errCh <- err
		wg.Done()
		return
	}

	// Configuration addresses are static ELF virtual addresses. Validate them
	// before starting the model; they will be translated while the child is
	// stopped immediately after exec.
	relocation, err := configureRelocation(config)
	if err != nil {
		log.Printf("Cannot configure ASLR-safe target addresses: %v", err)
		errCh <- err
		wg.Done()
		return
	}

	// Set cycles in ebpf
	err = setCycles(spec, config)
	if err != nil {
		errCh <- err
		wg.Done()
		return
	}

	// Set max entries in eBPF spec, retrieve signals, write desired trajectories
	var cReads []my_types.Signal
	var cWrites []my_types.Signal
	var nof_signals_read uint32
	var nof_signals_written uint32
	for _, group := range config.Reads {
		cReads = append(cReads, group.Signals...)
		nof_signals_read += uint32(len(group.Signals))
	}
	for _, group := range config.Writes {
		cWrites = append(cWrites, group.Signals...)
		nof_signals_written += uint32(len(group.Signals))
	}

	log.Printf("nof_signals_read %d, nof_signals_written %d", nof_signals_read, nof_signals_written)
	if err = spec.Variables["NOF_SIGNALS_READ"].Set(nof_signals_read); err != nil {
		log.Printf("Error setting variable setting variable NOF_SIGNALS_READ: %v", err)
		errCh <- err
		wg.Done()
		return
	}
	if err = spec.Variables["NOF_SIGNALS_WRITTEN"].Set(nof_signals_written); err != nil {
		log.Printf("Error setting variable setting variable NOF_SIGNALS_WRITTEN: %v", err)
		errCh <- err
		wg.Done()
		return
	}

	// Map specifications must be finalized before LoadAndAssign: that call
	// creates the kernel maps, and changing a spec afterwards cannot resize an
	// existing map.
	if err := configureSignalMapSizes(spec, nof_signals_read+nof_signals_written); err != nil {
		log.Printf("Cannot configure signal map sizes: %v", err)
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
	trajectory, err := extractTrajectory(rawTrajectory, config)
	if err != nil {
		errCh <- err
		wg.Done()
		return
	}
	log.Print("Input trajectory extracted successfully")

	// Get the trajectory map and use its spec as the template for inner maps.
	trajectoryMapSpec := spec.Maps["trajectory_map"]
	// create outer map
	trajectoryMap := probeObjs.TrajectoryMap
	if err != nil {
		log.Printf("Cannot create trajectory map (outer) map: %s", err)
		errCh <- err
		wg.Done()
		return
	}
	// create signal sequences
	// start preparing a template for the array positions
	innerMapKeys := make([]uint32, CYCLES)
	for p, _ := range innerMapKeys {
		innerMapKeys[p] = uint32(p)
	}
	for s := 0; s < int(nof_signals_read+nof_signals_written); s++ {
		// refine and clone the inner map spec to avoid reuse
		innerSpec := trajectoryMapSpec.InnerMap.Copy()
		innerSpec.MaxEntries = paddedEntries(CYCLES)
		inner, err := ebpf.NewMap(innerSpec)
		if err != nil {
			log.Printf("Cannot create sequence (inner) map: %s", err)
			errCh <- err
			wg.Done()
			return
		}
		// pin the inner map
		pinPath := "/sys/fs/bpf/sequence_values_" + strconv.FormatInt(int64(s), 10)
		if err := inner.Pin(pinPath); err != nil {
			log.Printf("Cannot pin inner map at %v", pinPath)
			errCh <- err
			wg.Done()
			return
		}
		// inject the trajectory
		if s >= int(nof_signals_read) { // only for signals to write
			sw := int(s - int(nof_signals_read))
			sName := cWrites[sw].Name
			log.Printf("sName: %v", sName)
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
		// insert single sequence array into trajectory map
		key := uint32(s)
		fd := inner.FD()
		value := uint32(fd)
		if err := trajectoryMap.Update(key, value, 0); err != nil {
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
		// defer inner map unpinning
		defer func() {
			if err := inner.Unpin(); err != nil {
				log.Printf("Cannot unpin inner map, err: %v", err)
			}
			log.Printf("Map unpinned from %s", pinPath)
		}()
		defer inner.Close()
	}
	modelExecutable, err := link.OpenExecutable(config.ModelPath)
	if err != nil {
		log.Printf("Error opening model executable: %s", err)
		errCh <- err
		wg.Done()
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
		errCh <- err
		wg.Done()
		return
	}
	runtimeAddresses, loadBias, err := relocation.runtimeAddresses(binCmd.Process.Pid)
	if err != nil {
		_ = abortStopped(binCmd)
		log.Printf("Cannot resolve target runtime addresses: %s", err)
		errCh <- err
		wg.Done()
		return
	}
	for p, runtimeAddress := range runtimeAddresses {
		if err = probeObjs.AddressMap.Update(uint32(p), runtimeAddress, 0); err != nil {
			_ = abortStopped(binCmd)
			log.Printf("Cannot update runtime address for signal %d: %v", p, err)
			errCh <- err
			wg.Done()
			return
		}
	}

	// Attach the uprobes only to this target while it is still stopped. The
	// address map above contains addresses relocated for this specific process,
	// so allowing another instance of the executable to trigger these programs
	// would make the programs dereference addresses from the wrong address space.
	targetPID := binCmd.Process.Pid
	var offset uint64
	var group_base int
	if nof_signals_read > 0 {
		for _, group := range config.Reads {
			cookie := uprobeCookie(group_base, len(group.Signals))
			log.Printf("Read group %d, %d signals, cookie: %d", group_base, len(group.Signals), cookie)
			offset, err = strconv.ParseUint(group.Offset, 10, 64) // base 10
			if err != nil {
				_ = abortStopped(binCmd)
				log.Printf("Error converting uprobe offset: %s", err)
				errCh <- err
				wg.Done()
				return
			}
			options := &link.UprobeOptions{Offset: offset, Cookie: cookie, PID: targetPID}
			var uprobeR link.Link
			if group.Retprobe {
				uprobeR, err = modelExecutable.Uretprobe(group.Symbol, probeObjs.UprobeRead, options)
			} else {
				uprobeR, err = modelExecutable.Uprobe(group.Symbol, probeObjs.UprobeRead, options)
			}
			if err != nil {
				_ = abortStopped(binCmd)
				log.Printf("Error setting the read probe: %v", err)
				errCh <- err
				wg.Done()
				return
			}
			log.Print("Read probe linked")
			defer uprobeR.Close()
			group_base += len(group.Signals)
		}
	}
	if nof_signals_written > 0 {
		for _, group := range config.Writes {
			cookie := uprobeCookie(group_base, len(group.Signals))
			log.Printf("Written group %d, %d signals, cookie: %d", group_base, len(group.Signals), cookie)
			offset, err = strconv.ParseUint(group.Offset, 10, 64) // base 10
			if err != nil {
				_ = abortStopped(binCmd)
				log.Printf("Error converting uprobe offset: %s", err)
				errCh <- err
				wg.Done()
				return
			}
			options := &link.UprobeOptions{Offset: offset, Cookie: cookie, PID: targetPID}
			var uprobeW link.Link
			if group.Retprobe {
				uprobeW, err = modelExecutable.Uretprobe(group.Symbol, probeObjs.UprobeWrite, options)
			} else {
				uprobeW, err = modelExecutable.Uprobe(group.Symbol, probeObjs.UprobeWrite, options)
			}
			if err != nil {
				_ = abortStopped(binCmd)
				log.Printf("Error setting the write probe: %v", err)
				errCh <- err
				wg.Done()
				return
			}
			log.Print("Write probe linked")
			defer uprobeW.Close()
			group_base += len(group.Signals)
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
		errCh <- err
		wg.Done()
		return
	}
	defer uprobe_timer.Close()

	detachErr := detachStopped(binCmd)
	ptraceThreadLocked = false
	runtime.UnlockOSThread()
	if detachErr != nil {
		_ = abortStopped(binCmd)
		log.Printf("Cannot detach from target after address setup: %s", detachErr)
		errCh <- detachErr
		wg.Done()
		return
	}
	// Start measuring only once the untraced model can execute.
	simulationStartTime := time.Now()

	// wait for non-interactive simulations to terminate
	if simulationMode == my_types.Falsification {
		// wait until simulation terminates
		if err := binCmd.Wait(); err != nil {
			if !cmdWasSigkilled(err) {
				log.Printf("Simulation finished with error: %s", err)
				errCh <- err
				wg.Done()
				stopSimulator(simulationStartTime, nof_signals_read, nof_signals_written, config)
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
		ctx := context.Background()
		if err := monitorSimulation(ctx, probeObjs, nof_signals_read, simulationDone, cancelSimulation); err != nil {
			errCh <- err
			wg.Done()
			stopSimulator(simulationStartTime, nof_signals_read, nof_signals_written, config)
			return
		}
	case my_types.Falsification:
		var outSignals my_types.OutputTrace
		for id, signal := range cReads {
			var signTrace my_types.Trace
			signTrace.SignName = signal.Name
			var signalKey uint32 = uint32(id)
			// get the trace from the eBPF map
			pinPath := "/sys/fs/bpf/sequence_values_" + strconv.FormatInt(int64(signalKey), 10)
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
					stopSimulator(simulationStartTime, nof_signals_read, nof_signals_written, config)
					return
				}
			}
			signTrace.Values = values
			//log.Printf("values %v", values)
			outSignals.Signals = append(outSignals.Signals, signTrace)
		}
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
			stopSimulator(simulationStartTime, nof_signals_read, nof_signals_written, config)
			return
		}
		// defer unpinnning
		defer func() {
			if err := probeObjs.StateRb.Unpin(); err != nil {
				log.Printf("Cannot unpin state perturbation buffer: %v", err)
			}
		}()

		// apply state perturbation
		go func(ctx context.Context, statePertCh <-chan []my_types.StateRecord, probeObjs probeObjects, errCh chan error, loadBias uint64) {

			for {
				select {
				case <-ctx.Done():
					return
				case perturbation, ok := <-statePertCh:
					if !ok {
						break // the simulation is still running but the channel was closed
					}
					// write records to a temp file
					tempFile, err := os.CreateTemp("", "model_state_records_*.bin")
					if err != nil {
						log.Printf("Cannot create temporary inject file for state records: %v", err)
						break
					}
					defer tempFile.Close()
					for _, r := range perturbation {
						runtimeAddress, ok := addUint64(r.Addr, loadBias)
						if !ok {
							log.Printf("State perturbation address %#x overflows after relocation", r.Addr)
							break
						}
						binary.Write(tempFile, binary.LittleEndian, r.Time)
						binary.Write(tempFile, binary.LittleEndian, r.ValueSize)
						binary.Write(tempFile, binary.LittleEndian, runtimeAddress)
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
		}(ctx, statePertCh, probeObjs, errChi, loadBias)

		// monitor simulation
		go asyncMonitorSimulation(wgm, errChm, ctx, probeObjs, nof_signals_read, simulationDone, cancelSimulation)

		// wait for simulation to terminate
		wgm.Wait()
		// return the error if occured, otherwise send simulation task terminated
		if err := <-errChm; err != nil {
			errCh <- err
		} else {
			wg.Done()
		}
		stopSimulator(simulationStartTime, nof_signals_read, nof_signals_written, config)
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
			stopSimulator(simulationStartTime, nof_signals_read, nof_signals_written, config)
			return
		}
		// defer unpinnning
		defer func() {
			if err := probeObjs.InjRb.Unpin(); err != nil {
				log.Printf("Cannot unpin perturbation buffer: %v", err)
			}
		}()

		// apply signal perturbation
		go func(ctx context.Context, pertCh <-chan map[string]interface{}, probeObjs probeObjects, errCh chan error, nof_signals_written uint32) {

			for {
				select {
				case <-ctx.Done():
					return
				case perturbation, ok := <-pertCh:
					if !ok {
						break // the simulation is still running but the channel was closed
					}
					// extract perturbation records
					pertRecords, err := extractPerturbationRecords(perturbation, nof_signals_written, cWrites)
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
						strconv.FormatInt(int64(nof_signals_written), 10),
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
		}(ctx, pertCh, probeObjs, errChi, nof_signals_written)
		// monitor simulation
		go asyncMonitorSimulation(wgm, errChm, ctx, probeObjs, nof_signals_read, simulationDone, cancelSimulation)

		// wait for simulation to terminate
		wgm.Wait()
		// return the error if occured, otherwise send simulation task terminated
		if err := <-errChm; err != nil {
			errCh <- err
		} else {
			wg.Done()
		}

		stopSimulator(simulationStartTime, nof_signals_read, nof_signals_written, config)
		return
	}

	// terminate
	wg.Done()
	stopSimulator(simulationStartTime, nof_signals_read, nof_signals_written, config)
	return
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
		record.Values = make([]float64, nof_signals_written)
		for signal_pos, signal := range cWrites {
			if vals, ok := signalVals[signal.Name]; ok {
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

func asyncMonitorSimulation(wg *sync.WaitGroup, errCh chan<- error, ctx context.Context, probeObjs probeObjects, nof_signals_read uint32, simulationDone <-chan error, stopSimulation context.CancelFunc) {

	defer wg.Done()
	err := monitorSimulation(ctx, probeObjs, nof_signals_read, simulationDone, stopSimulation)
	errCh <- err
}

func monitorSimulation(ctx context.Context, probeObjs probeObjects, nof_signals_read uint32, simulationDone <-chan error, stopSimulation context.CancelFunc) error {

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
	var completionErr error
	simulationKey := "simulation:" + simulationId

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
			_vals := make([]float64, nof_signals_read)
			for p, _ := range _vals {
				_tbuf := bytes.NewReader(raw[8+p*8 : 16+p*8])
				binary.Read(_tbuf, binary.LittleEndian, &_vals[p])
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
				return fmt.Errorf("read simulation ring buffer: %w", err)
			}
			receivedRecords := writtenRecords + uint32(len(records))
			if receivedRecords >= CYCLES {
				break
			}
			select {
			case waitErr := <-simulationDone:
				if waitErr != nil {
					completionErr = fmt.Errorf("simulation exited before monitoring completed: %w", waitErr)
				} else {
					completionErr = fmt.Errorf("simulation produced %d of %d expected records", receivedRecords, CYCLES)
				}
				break monitorLoop
			default:
			}
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

	return completionErr
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
