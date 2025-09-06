//go:build amd64 && linux

package main

import (
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/dariofad/ebpf_simulator/server"
)

var VERBOSE bool
var PORT uint16 = 8080

func main() {

	parseCmdLineOptions()
	configureLogger()
	server.StartServer(PORT)
	// todo handle requests to stop the server
}

func parseCmdLineOptions() {

	verbP := flag.Bool("v", false, "Enable verbose mode")
	flag.Parse()
	VERBOSE = *verbP
	server.VERBOSE = VERBOSE

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
