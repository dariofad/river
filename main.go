//go:build amd64 && linux

package main

import (
	"flag"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/dariofad/ebpf_simulator/my_types"
	"github.com/dariofad/ebpf_simulator/server"
	"github.com/dariofad/ebpf_simulator/simulator"
)

var VERBOSE bool
var BENCH bool
var MONITORING_PORT uint16 = 8080
var FALSIFICATION_PORT uint16 = 8081
var STATE_PERTURBATION_PORT uint16 = 8082
var SIGNAL_PERTURBATION_PORT uint16 = 8083

func main() {

	// configure the server
	parseCmdLineOptions()
	configureLogger()
	simulator.RemoveMemlock()
	// start the services
	go server.StartService(MONITORING_PORT, my_types.Monitoring)
	go server.StartService(FALSIFICATION_PORT, my_types.Falsification)
	go server.StartService(STATE_PERTURBATION_PORT, my_types.StatePerturbation)
	go server.StartService(SIGNAL_PERTURBATION_PORT, my_types.SignalPerturbation)
	// todo: add a service to stop unbounded simulations
	// wait indefinitely
	var wg sync.WaitGroup
	wg.Add(1)
	wg.Wait()
}

func parseCmdLineOptions() {

	verbP := flag.Bool("v", false, "Enable verbose mode")
	benchP := flag.Bool("b", false, "Enable bench mode")
	flag.Parse()
	VERBOSE = *verbP
	BENCH = *benchP
	server.VERBOSE = VERBOSE
	simulator.VERBOSE = VERBOSE
	server.BENCH = BENCH
	simulator.BENCH = BENCH

}

type logWriter struct {
}

func (writer logWriter) Write(bytes []byte) (int, error) {

	// min, sec, micro
	return fmt.Print(time.Now().UTC().Format("04:05.000") +
		": " + string(bytes))
}

func configureLogger() {

	// set new prefix for log records
	log.SetFlags(0)
	log.SetOutput(new(logWriter))
	// log cmd options
	if VERBOSE {
		log.Print("VERBOSE MODE")
	}
}
