//go:build amd64 && linux

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load eBPF collection spec
	spec, err := loadProbe()
	if err != nil {
		log.Fatalf("loading collectionSpec: %s", err)
	}

	// Get the binary path
	rawBinPath, err := os.ReadFile(".BIN_PATH")
	if err != nil {
		log.Fatal("Error setting the ACC path")
		panic(err)
	}
	binPath := string(rawBinPath)
	fmt.Println("ACC binary path:", binPath)

	// Get the symbol name
	rawSymbol, err := os.ReadFile(".BIN_SYM")
	if err != nil {
		log.Fatal("Error setting the symbol name")

	}
	symbol := string(rawSymbol)
	fmt.Println("ACC symbol name:", symbol)

	// Get the addresses
	rawAddrs, err := os.ReadFile(".ADDRS.json")
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
	OFFSET, e4 := strconv.ParseUint(addrs["OFFSET"], 10, 64) // NB, base 10
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil {
		log.Fatalf("Error converting the addresses e1=%v, e2=%v, e3=%v, e4=%v\n ", e1, e2, e3, e4)
	}

	// Set the addresses in the spec
	if err = spec.Variables["ADDR_BASE"].Set(ADDR_BASE); err != nil {
		log.Fatalf("setting variable: %s", err)
	}
	if err = spec.Variables["ADDR_OBJ"].Set(ADDR_OBJ); err != nil {
		log.Fatalf("setting variable: %s", err)
	}
	if err = spec.Variables["ADDR_DREL"].Set(ADDR_DREL); err != nil {
		log.Fatalf("setting variable: %s", err)
	}

	// Load pre-compiled programs and maps into the kernel
	var objs probePrograms
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatalf("loading programs: %s", err)
	}
	defer objs.Close()

	// Open an ELF binary and read its symbols
	ex, err := link.OpenExecutable(binPath)
	if err != nil {
		log.Fatalf("opening executable: %s", err)
	}

	// Link the uprobe
	uprobe, err := ex.Uprobe(symbol, objs.UprobeDrelProbe, &link.UprobeOptions{Offset: OFFSET})
	if err != nil {
		fmt.Println("cannot set the uprobe")
		return
	}
	defer uprobe.Close()

	// Wait for stop signal (and deallocate eBPF objects berfore
	// termination)
	stop := make(chan os.Signal, 5)
	signal.Notify(stop, os.Interrupt)
	for {
		select {
		case <-stop:
			log.Print("Received signal, exiting..")
			return
		default:
			log.Println("Running")
			time.Sleep(1 * time.Second)
		}
	}
}
