package simulator

import (
	"encoding/json"
	"errors"
	"log"
	"os"
	"os/exec"
	"strconv"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

var VERBOSE bool

// Allow the simulator process to to lock memory for eBPF resources
func RemoveMemlock() {

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}
}

func Run(data map[string]interface{}) {

	// Load eBPF collection spec
	spec, err := loadProbe()
	if err != nil {
		log.Fatalf("loading collectionSpec: %s", err)
	}

	// Get the binary path
	rawBinPath, err := os.ReadFile("simulator/.BIN_PATH")
	if err != nil {
		log.Fatal("Error setting the dualACC")
		panic(err)
	}
	binPath := string(rawBinPath)
	log.Println("ACC binary path:", binPath)

	// Get the symbol name
	rawSymbol, err := os.ReadFile("simulator/.BIN_SYM")
	if err != nil {
		log.Fatal("Error setting the symbol name")

	}
	symbol := string(rawSymbol)
	log.Println("ACC symbol name:", symbol)

	// Get the addresses
	rawAddrs, err := os.ReadFile("simulator/.ADDRS.json")
	if err != nil {
		log.Fatal("Error reading addresses")
	}
	var addrs map[string]string
	if err = json.Unmarshal(rawAddrs, &addrs); err != nil {
		log.Fatal("Error marhsaling addresses here", err)
	}
	if err != nil {
		log.Fatal("Error marhsaling addresses")
	}
	ADDR_BASE, e1 := strconv.ParseUint(addrs["ADDR_BASE"], 16, 64)
	ADDR_OBJ, e2 := strconv.ParseUint(addrs["ADDR_OBJ"], 16, 64)
	ADDR_DREL, e3 := strconv.ParseUint(addrs["ADDR_DREL"], 16, 64)
	OFFSET, e4 := strconv.ParseUint(addrs["OFFSET"], 10, 64)                             // base 10
	MINOR_TO_MAJOR_RATIO, e5 := strconv.ParseUint(addrs["MINOR_TO_MAJOR_RATIO"], 10, 64) // base 10
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || e5 != nil {
		log.Fatalf("Error converting the addresses e1=%v, e2=%v, e3=%v, e4=%v, e5=%v\n ", e1, e2, e3, e4, e5)
	}

	// Set values in the spec
	if err = spec.Variables["ADDR_BASE"].Set(ADDR_BASE); err != nil {
		log.Fatalf("setting variable: %s", err)
	}
	if err = spec.Variables["ADDR_OBJ"].Set(ADDR_OBJ); err != nil {
		log.Fatalf("setting variable: %s", err)
	}
	if err = spec.Variables["ADDR_DREL"].Set(ADDR_DREL); err != nil {
		log.Fatalf("setting variable: %s", err)
	}
	if err = spec.Variables["MINOR_TO_MAJOR_RATIO"].Set(uint32(MINOR_TO_MAJOR_RATIO)); err != nil {
		log.Fatalf("setting variable: %s", err)
	}

	// Set the simulation number of cycles
	var MAX_CYCLES uint32
	dataPoints, ok := data["datapoints"].([]interface{})
	if ok {
		if len(dataPoints) != 2 {
			log.Print("Unrecognized datapoints size")
			return
		}
		numPoints, ok := dataPoints[1].(float64)
		if !ok {
			log.Print("Unrecognized datapoints content")
			return
		}
		MAX_CYCLES = uint32(numPoints)
		log.Printf("Found %d datapoints", MAX_CYCLES)
	} else {
		log.Print("Cannot detect the number of datapoints")
		return
	}
	if err = spec.Variables["MAX_CYCLES"].Set(MAX_CYCLES); err != nil {
		log.Fatalf("setting variable: %s", err)
	}

	// fix the spec for the d_rel_map
	dRelMapSpec, ok := spec.Maps["d_rel_map"]
	if !ok {
		log.Print("Cannot get the d_rel map spec")
		return
	}
	dRelMapSpec.MaxEntries = MAX_CYCLES

	// load eBPF objects (maps + programs) into the kernel
	probeObjs := probeObjects{}
	if err := spec.LoadAndAssign(&probeObjs, nil); err != nil {
		log.Printf("Cannot load eBPF objects, err: %v", err)
		return
	}
	defer probeObjs.Close()

	// Inject datapoints (with batch update)
	keys := make([]uint32, MAX_CYCLES)
	var tmpKey uint32 = 0
	for tmpKey < MAX_CYCLES {
		keys[tmpKey] = tmpKey
		tmpKey += 1
	}
	values, err := getDRel(data, MAX_CYCLES)
	if err != nil {
		return
	}
	if VERBOSE {
		log.Println("d_rel values:", values)
	}
	// Perform batch update
	probeObjs.D_relMap.BatchUpdate(keys, values, &ebpf.BatchOptions{
		Flags: uint64(ebpf.UpdateAny),
	})

	// Open executable and link the uproble
	ex, err := link.OpenExecutable(binPath)
	if err != nil {
		log.Fatalf("opening executable: %s", err)
	}
	// Link the uprobe
	uprobe, err := ex.Uprobe(symbol, probeObjs.UprobeDrelProbe, &link.UprobeOptions{Offset: OFFSET})
	if err != nil {
		log.Fatal("cannot set the uprobe")
		return
	}
	defer uprobe.Close()

	// Run the simulation and wait until it terminates
	binCmd := exec.Command(binPath)
	binCmd.Stdout = os.Stdout
	binCmd.Stderr = os.Stderr
	log.Println("Starting simulation")
	err = binCmd.Run()
	if err != nil {
		log.Printf("Simulation ended (%s)", err)
	}
}

// Extract d_rel values from the simulation raw data
func getDRel(data map[string]interface{}, dataPoints uint32) ([]float64, error) {

	values := make([]float64, dataPoints)
	rawVect, ok := data["d_rel"].([]interface{})
	if ok {
		log.Printf("Found %T datapoints", rawVect)
		for pos, rawVal := range rawVect {
			floatVal, ok := rawVal.(float64)
			if !ok {
				return nil, errors.New("Cannot convert value to float64")
			}
			values[pos] = floatVal
		}
	} else {
		log.Print("Cannot extract the d_rel values")
		return nil, errors.New("Cannot find d_rel in map")
	}
	return values, nil
}
