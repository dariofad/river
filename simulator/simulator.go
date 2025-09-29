package simulator

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
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
	"github.com/redis/go-redis/v9"
)

var VERBOSE bool

// Allow the simulator process to to lock memory for eBPF resources
func RemoveMemlock() {

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}
}

func Run(data map[string]interface{}) (*Result, error) {

	// Load eBPF collection spec
	spec, err := loadProbe()
	if err != nil {
		log.Printf("loading collectionSpec: %s", err)
		return nil, errors.New("Simulation failed: cannot retrieve collection spec")
	}

	// Get the binary path
	rawBinPath, err := os.ReadFile("simulator/.BIN_PATH")
	if err != nil {
		log.Print("Error setting the dualACC")
		return nil, errors.New("Simulation failed: cannot find the executable to simulate")
	}
	binPath := string(rawBinPath)
	log.Println("ACC binary path:", binPath)

	// Get the symbol name
	rawSymbol, err := os.ReadFile("simulator/.BIN_SYM")
	if err != nil {
		log.Print("Error setting the symbol name")
		return nil, errors.New("Simulation failed: cannot read the symbol name")
	}
	symbol := string(rawSymbol)
	log.Println("ACC symbol name:", symbol)

	// Get the addresses
	rawAddrs, err := os.ReadFile("simulator/.ADDRS.json")
	if err != nil {
		log.Print("Error reading addresses")
		return nil, errors.New("Simulation failed: cannot read the addresses")
	}
	var addrs map[string]string
	if err = json.Unmarshal(rawAddrs, &addrs); err != nil {
		log.Print("Error marhsaling addresses here", err)
		return nil, errors.New("Simulation failed: marshaling")
	}
	ADDR_DREL, e1 := strconv.ParseUint(addrs["ADDR_DREL"], 16, 64)
	ADDR_AEGO, e2 := strconv.ParseUint(addrs["ADDR_AEGO"], 16, 64)
	ADDR_VEGO, e3 := strconv.ParseUint(addrs["ADDR_VEGO"], 16, 64)
	OFFSET_STEP, e4 := strconv.ParseUint(addrs["OFFSET_STEP"], 10, 64)                   // base 10
	OFFSET_MAIN, e5 := strconv.ParseUint(addrs["OFFSET_MAIN"], 10, 64)                   // base 10
	MINOR_TO_MAJOR_RATIO, e6 := strconv.ParseUint(addrs["MINOR_TO_MAJOR_RATIO"], 10, 64) // base 10
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || e5 != nil || e6 != nil {
		log.Printf("Error converting the addresses e1=%v, e2=%v, e3=%v, e4=%v, e5=%v, e6=%v\n ", e1, e2, e3, e4, e5, e6)
		return nil, errors.New("Simulation failed: error converting the addresses")
	}

	// Set values in the spec
	if err = spec.Variables["ADDR_DREL"].Set(ADDR_DREL); err != nil {
		log.Printf("setting variable: %s", err)
		return nil, errors.New("Simulation failed: error setting value in spec")
	}
	if err = spec.Variables["ADDR_AEGO"].Set(ADDR_AEGO); err != nil {
		log.Printf("setting variable: %s", err)
		return nil, errors.New("Simulation failed: error setting value in spec")
	}
	if err = spec.Variables["ADDR_VEGO"].Set(ADDR_VEGO); err != nil {
		log.Printf("setting variable: %s", err)
		return nil, errors.New("Simulation failed: error setting value in spec")
	}
	if err = spec.Variables["MINOR_TO_MAJOR_RATIO"].Set(uint32(MINOR_TO_MAJOR_RATIO)); err != nil {
		log.Printf("setting variable: %s", err)
		return nil, errors.New("Simulation failed: error setting value in spec")
	}

	// Set the simulation mode
	var MODE uint16 = 0
	rawMode, ok := data["mode"].(interface{})
	if ok {
		tmp_v, ok := rawMode.(float64)
		MODE = uint16(tmp_v)
		if !ok || (MODE != 0 && MODE != 1) {
			log.Print("Unrecognized mode")
			return nil, errors.New("Simulation failed: unrecognized mode")
		}
	} else {
		log.Print("Cannot detect the mode")
		return nil, errors.New("Simulation failed: unrecognized input")
	}
	if err = spec.Variables["MODE"].Set(MODE); err != nil {
		log.Printf("setting variable: %s", err)
		return nil, errors.New("Simulation failed: error setting value in spec")
	}

	// Set the simulation number of cycles
	var MAX_CYCLES uint32
	dataPoints, ok := data["datapoints"].([]interface{})
	if ok {
		if len(dataPoints) != 2 {
			log.Print("Unrecognized datapoints size")
			return nil, errors.New("Simulation failed: unrecognized input")
		}
		numPoints, ok := dataPoints[1].(float64)
		if !ok {
			log.Print("Unrecognized datapoints content")
			return nil, errors.New("Simulation failed: unrecognized input")
		}
		MAX_CYCLES = uint32(numPoints)
		log.Printf("Found %d datapoints", MAX_CYCLES)
	} else {
		log.Print("Cannot detect the number of datapoints")
		return nil, errors.New("Simulation failed: unrecognized input")
	}
	if err = spec.Variables["MAX_CYCLES"].Set(MAX_CYCLES); err != nil {
		log.Printf("setting variable: %s", err)
		return nil, errors.New("Simulation failed: error setting value in spec")
	}

	// Fix the spec for the maps based on the data
	// Relative distance (noise)
	dRelMapSpec, ok := spec.Maps["d_rel_noise_map"]
	if !ok {
		log.Print("Cannot get the d_rel_noise map spec")
		return nil, errors.New("Simulation failed: cannot find map in spec")
	}
	dRelMapSpec.MaxEntries = MAX_CYCLES
	if MODE == 0 {
		// Acceleration Ego
		aEgoMapSpec, ok := spec.Maps["a_ego_map"]
		if !ok {
			log.Print("Cannot get the a_ego map spec")
			return nil, errors.New("Simulation failed: cannot find map in spec")
		}
		// Speed Ego
		aEgoMapSpec.MaxEntries = MAX_CYCLES
		vEgoMapSpec, ok := spec.Maps["v_ego_map"]
		if !ok {
			log.Print("Cannot get the v_ego map spec")
			return nil, errors.New("Simulation failed: cannot find map in spec")
		}
		vEgoMapSpec.MaxEntries = MAX_CYCLES
	}

	// load eBPF objects (maps + programs) into the kernel
	probeObjs := probeObjects{}
	if err := spec.LoadAndAssign(&probeObjs, nil); err != nil {
		log.Printf("Cannot load eBPF objects, err: %v", err)
		return nil, errors.New("Simulation failed: cannot load eBPF objects")
	}
	defer probeObjs.Close()

	// Prepare noise for injection datapoints (with batch update)
	keys := make([]uint32, MAX_CYCLES)
	var tmpKey uint32 = 0
	for tmpKey < MAX_CYCLES {
		keys[tmpKey] = tmpKey
		tmpKey += 1
	}
	values, err := getDRel(data, MAX_CYCLES)
	if err != nil {
		return nil, errors.New("Simulation failed: cannot convert d_rel_noise data points")
	}
	if VERBOSE {
		log.Println("d_rel_noise values:", values)
	}
	// Perform batch update
	_, err = probeObjs.D_relNoiseMap.BatchUpdate(keys, values, &ebpf.BatchOptions{
		Flags: uint64(ebpf.UpdateAny),
	})
	if err != nil {
		return nil, errors.New("Simulation failed: cannot perform batch update for d_rel_noise")
	}

	// Open executable and link the uprobe
	ex, err := link.OpenExecutable(binPath)
	if err != nil {
		log.Fatalf("opening executable: %s", err)
		return nil, errors.New("Simulation failed: cannot open executable")
	}
	// Link the step() uprobe
	uprobe_step, err := ex.Uprobe(symbol, probeObjs.UprobeDrelProbe, &link.UprobeOptions{Offset: OFFSET_STEP})
	if err != nil {
		log.Fatal("cannot set the uprobe to step()")
		return nil, errors.New("Simulation failed: cannot attach to step()")
	}
	defer uprobe_step.Close()
	// Link the main() uprobe
	uprobe_main, err := ex.Uprobe(symbol, probeObjs.UprobeOutputProbe, &link.UprobeOptions{Offset: OFFSET_MAIN})
	if err != nil {
		log.Fatal("cannot set the uprobe to main()")
		return nil, errors.New("Simulation failed: cannot attach to main()")
	}
	defer uprobe_main.Close()

	// Run the simulation
	ctx, cancelSimulation := context.WithCancel(context.Background())
	defer cancelSimulation()
	binCmd := exec.CommandContext(ctx, binPath)
	binCmd.Stdout = os.Stdout
	binCmd.Stderr = os.Stderr
	// Start the command
	log.Print("Starting simulation")
	if err := binCmd.Start(); err != nil {
		log.Printf("Failed to start simulation command: %v", err)
		return nil, errors.New("Simulation start command failed")
	}
	// Prepare the arrays for the result and start
	a_ego := make([]float64, MAX_CYCLES)
	v_ego := make([]float64, MAX_CYCLES)
	if MODE == 0 {
		// wait until simulation terminates
		if err := binCmd.Wait(); err != nil {
			if err != nil && !cmdWasSigkilled(err) {
				log.Printf("Simulation finished with error: %v", err)
				return nil, errors.New("Simulation failed with error")
			}
		} else {
			fmt.Println("Simulation completed successfully")
		}
	} else {
		// don't wait until it terminates
		log.Printf("Simulation running")
	}

	var records []ModelRecord
	// Read the simulation output trace
	if MODE == 0 {
		for pos := uint32(0); pos < MAX_CYCLES; pos++ {
			err := probeObjs.A_egoMap.Lookup(&pos, &a_ego[pos])
			if err != nil {
				log.Printf("a_ego: lookup failed: %v\n", err)
				return nil, errors.New("Error reading simulation results: cannot complete reads")
			}
		}
		for pos := uint32(0); pos < MAX_CYCLES; pos++ {
			err := probeObjs.V_egoMap.Lookup(&pos, &v_ego[pos])
			if err != nil {
				log.Printf("v_ego: lookup failed: %v\n", err)
				return nil, errors.New("Error reading simulation results: cannot complete reads")
			}
		}
	} else {
		// Create the Redis client
		redisClient := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
		// Get the simulation id
		simulationId := strconv.Itoa(0) // todo fix
		// Get the background context
		bg_ctx := context.Background()
		// Add a new redis set fot the current run
		if err := redisClient.SAdd(bg_ctx, "simulation", simulationId).Err(); err != nil {
			log.Print("Failed to add simulation set to Redis:", err)
			return nil, errors.New("Error adding new simulation set to Redis")
		}
		// Create a ring buffer reader
		rbReader, err := ringbuf.NewReader(probeObjs.RecordRb)
		if err != nil {
			log.Printf("Failed to create ring buffer reader: %v", err)
			return nil, errors.New("Error creating the ring buffer reader")
		}
		defer rbReader.Close()
		// Read events from the ring buffer
		for {
			rbReader.SetDeadline(time.Now().Add(250 * time.Millisecond))
			record, err := rbReader.Read()
			if err != nil {
				// check if simulation is still runnning
				if !(binCmd.ProcessState == nil || !binCmd.ProcessState.Exited()) {
					break
				}
			}
			// Parse the event
			var mrec ModelRecord
			err = binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &mrec)
			if err != nil {
				log.Printf("Stop reading records: %v", err)
				break
			}
			records = append(records, mrec)
		}
		// Write records to Redis
		simulationKey := "simulation:" + simulationId
		if err = writeToRedis(bg_ctx, redisClient, simulationKey, records); err != nil {
			return nil, errors.New("Error writing records to Redis")
		}
		// Empty local record slice
		records = []ModelRecord{}
	}

	// Return the output trace back to the server
	result := Result{
		AEgo: a_ego,
		VEgo: v_ego,
	}
	return &result, nil
}

// Write a slice of records to Redis
func writeToRedis(ctx context.Context, redisClient *redis.Client, simulationKey string, records []ModelRecord) error {

	// convert records to string representation and add them to a Redis sorted set
	var z []redis.Z
	for _, rec := range records {
		z = append(z, redis.Z{Score: float64(rec.Time), Member: ModelRecordToCSVString(rec)})
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

// Extract d_rel_noise values from the simulation raw data
func getDRel(data map[string]interface{}, dataPoints uint32) ([]float64, error) {

	values := make([]float64, dataPoints)
	rawVect, ok := data["d_rel_noise"].([]interface{})
	if ok {
		for pos, rawVal := range rawVect {
			floatVal, ok := rawVal.(float64)
			if !ok {
				return nil, errors.New("Cannot convert value to float64")
			}
			values[pos] = floatVal
		}
	} else {
		log.Print("Cannot extract the d_rel_noise values")
		return nil, errors.New("Cannot find d_rel_noise in map")
	}
	return values, nil
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
