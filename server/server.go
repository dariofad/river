package server

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/dariofad/river/manifest"
	"github.com/dariofad/river/my_types"
	"github.com/dariofad/river/simulator"
	"github.com/vmihailenco/msgpack/v5"
	"gopkg.in/yaml.v3"
)

var VERBOSE bool
var BENCH bool
var BUSY sync.Mutex

func StartService(port uint16, srv my_types.Service) {

	// start tcp server
	listener, err := net.Listen("tcp", ":"+strconv.Itoa(int(port)))
	if err != nil {
		log.Fatal("Server cannot setup the listener")
	}
	defer listener.Close()
	log.Printf("Server listening (%s mode, %d port)", srv.String(), int(port))

	// handle connections
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("%s server accepted connection, %s", srv.String(), err)
			continue
		}
		log.Printf("[->] %s server accepted connection", srv.String())

		switch srv {
		case my_types.Monitoring:
			handleMonitoring(conn)
		case my_types.Falsification:
			handleFalsification(conn)
		case my_types.StatePerturbation:
			handleStatePerturbation(conn)
		case my_types.SignalPerturbation:
			handleSignalPerturbation(conn)
		default:
			log.Fatalf("Error Cannot start non-existing server mode")
		}
	}
}

func timeTrack(start time.Time, name string) {

	elapsed := time.Since(start)
	log.Printf("|__func %s took %.3f ms\n", name, float64(elapsed.Nanoseconds())/1e6)
}

// Reads the connection incoming data. Returns the received data
// length (in bytes), and the related byte array
func getData(ctx context.Context, conn net.Conn) (uint32, []byte, error) {

	defer timeTrack(time.Now(), "getData()")

	// get the data length (expected to be a uint32)
	var dataLenBuf [4]byte
	n, err := io.ReadFull(conn, dataLenBuf[:])
	if err != nil {
		select {
		case <-ctx.Done():
			log.Print("getData() stopped due to end of simulation")
			return 0, nil, nil
		default:
			log.Println("Data length read error:",
				err,
				"bytes read:",
				n)
			return 0, nil, err

		}
	}
	dataLen := binary.BigEndian.Uint32(dataLenBuf[:])
	if VERBOSE {
		log.Println("DataLenBuf:", dataLenBuf)
	}
	log.Printf("Receiving %d bytes (%.3f MB)", dataLen, float64(dataLen)/(1024*1024))

	// get the data
	rawData := make([]byte, dataLen)
	if _, err := io.ReadFull(conn, rawData); err != nil {
		log.Println("Body reading error:", err)
		return dataLen, nil, err
	}
	log.Println("Data received")

	return dataLen, rawData, nil
}

// Deserializes the received raw data using MessagePack
func deserialize(rawData []byte) (map[string]interface{}, error) {

	defer timeTrack(time.Now(), "deserialize()")

	data := make(map[string]interface{})
	dec := msgpack.NewDecoder(bytes.NewReader(rawData))
	err := dec.Decode(&data)
	if err != nil {
		log.Println("Decoding failed, error:", err)
		return nil, err
	} else {
		log.Println("Data deserialized")
		if VERBOSE {
			log.Println(data)
		}
	}

	return data, nil

}

// The first request carries the edited YAML and its trajectory together.
// TODO(security): Prevent arbitrary binary execution via client-supplied manifests.
// Currently, `artifact.binary` from the untrusted manifest YAML is compiled into
// `config.ModelPath` and executed directly by the simulator.
// A malicious client can craft a manual manifest pointing `artifact.binary` to any
// existing ELF binary on the host (with its SHA-256 `build_id` and a valid symbol)
// to achieve arbitrary command execution. Once the architecture stabilizes, restrict
// `artifact.binary` to a server-controlled allowlist or trusted model directory.
func prepareRequest(rawData []byte) (map[string]interface{}, *my_types.Configuration, error) {
	var request struct {
		Manifest   string                 `msgpack:"manifest"`
		Trajectory map[string]interface{} `msgpack:"trajectory"`
	}
	if err := msgpack.Unmarshal(rawData, &request); err != nil {
		return nil, nil, fmt.Errorf("decode simulation request: %w", err)
	}
	if request.Manifest == "" || request.Trajectory == nil {
		return nil, nil, fmt.Errorf("simulation request requires manifest YAML and a trajectory map")
	}
	var m manifest.Manifest
	if err := yaml.Unmarshal([]byte(request.Manifest), &m); err != nil {
		return nil, nil, fmt.Errorf("parse manifest: %w", err)
	}
	config, err := manifest.CompileConfiguration(&m)
	if err != nil {
		return nil, nil, err
	}
	sanitizedTrajectory := make(map[string]interface{}, len(request.Trajectory))
	for key, values := range request.Trajectory {
		cleanKey, keyErr := sanitizeCatalogPath(key)
		if keyErr != nil {
			return nil, nil, fmt.Errorf("trajectory key: %w", keyErr)
		}
		sanitizedTrajectory[cleanKey] = values
	}
	return sanitizedTrajectory, config, nil
}

func sanitizeCatalogPath(path string) (string, error) {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return "", fmt.Errorf("empty catalog path")
	}
	if len(trimmed) > 256 {
		return "", fmt.Errorf("catalog path exceeds maximum length")
	}
	for _, r := range trimmed {
		if unicode.IsControl(r) || (!unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '.' && r != '_') {
			return "", fmt.Errorf("catalog path %q contains invalid characters", trimmed)
		}
	}
	return trimmed, nil
}

// Deserializes the received raw data using MessagePack and resolves/validates
// each state perturbation record against the compiled manifest configuration.
func deserializeState(rawData []byte, config *my_types.Configuration) ([]my_types.StateRecord, error) {

	defer timeTrack(time.Now(), "deserializeState()")

	data := make([]my_types.StateRecord, 0)
	dec := msgpack.NewDecoder(bytes.NewReader(rawData))
	err := dec.Decode(&data)
	if err != nil {
		log.Println("Decoding failed, error:", err)
		return nil, err
	}
	cycles, _ := strconv.ParseUint(config.NofCycles, 10, 32)
	for i := range data {
		record := &data[i]
		if cycles > 0 && uint64(record.Time) >= cycles {
			return nil, fmt.Errorf("state perturbation time %d is out of range (cycles: %d)", record.Time, cycles)
		}
		if strings.TrimSpace(record.Name) != "" {
			cleanPath, pathErr := sanitizeCatalogPath(record.Name)
			if pathErr != nil {
				return nil, fmt.Errorf("state perturbation: %w", pathErr)
			}
			entry, ok := config.Catalog[cleanPath]
			if !ok {
				return nil, fmt.Errorf("state perturbation %q is not a writable entry in the manifest catalog", cleanPath)
			}
			catalogAddr, parseErr := strconv.ParseUint(entry.Addr, 0, 64)
			if parseErr != nil {
				return nil, fmt.Errorf("state perturbation %q has invalid catalog address %q: %w", cleanPath, entry.Addr, parseErr)
			}
			if record.Addr != 0 && record.Addr != catalogAddr {
				return nil, fmt.Errorf("state perturbation %q specifies address %#x, which does not match catalog address %#x", cleanPath, record.Addr, catalogAddr)
			}
			record.Addr = catalogAddr
			record.Name = cleanPath
			if record.Type == "" {
				record.Type = entry.Type
			} else if record.Type != entry.Type {
				return nil, fmt.Errorf("state perturbation %q has TYPE %q; catalog requires %q", cleanPath, record.Type, entry.Type)
			}
			info, typeErr := my_types.ParseSignalType(record.Type)
			if typeErr != nil {
				return nil, fmt.Errorf("state perturbation %q: %w", cleanPath, typeErr)
			}
			if record.ValueSize == 0 {
				record.ValueSize = info.Size
			} else if record.ValueSize != info.Size {
				return nil, fmt.Errorf("state perturbation %q has VALUE_SIZE %d; %s requires %d", cleanPath, record.ValueSize, record.Type, info.Size)
			}
			if _, typeErr = my_types.EncodeSignalValue(record.Value, record.Type); typeErr != nil {
				return nil, fmt.Errorf("state perturbation %q: %w", cleanPath, typeErr)
			}
		} else {
			if record.Addr == 0 {
				return nil, fmt.Errorf("state perturbation requires either NAME (catalog path) or ADDR")
			}
			info, typeErr := my_types.ParseSignalType(record.Type)
			if typeErr != nil {
				return nil, fmt.Errorf("state perturbation at %#x: %w", record.Addr, typeErr)
			}
			if record.ValueSize != info.Size {
				return nil, fmt.Errorf("state perturbation at %#x has VALUE_SIZE %d; %s requires %d", record.Addr, record.ValueSize, record.Type, info.Size)
			}
			if _, typeErr = my_types.EncodeSignalValue(record.Value, record.Type); typeErr != nil {
				return nil, fmt.Errorf("state perturbation at %#x: %w", record.Addr, typeErr)
			}
		}
	}
	log.Println("State Data deserialized")
	if VERBOSE {
		log.Println(data)
	}

	return data, nil

}

// Serializes a result using MessagePack
func serialize(result my_types.OutputTrace) (*bytes.Buffer, error) {

	defer timeTrack(time.Now(), "serialize()")

	var response bytes.Buffer
	enc := msgpack.NewEncoder(&response)
	err := enc.Encode(result)
	if err != nil {
		fmt.Println("Result encode error:", err)
		return nil, err
	}
	log.Println("Result serialized")
	// if VERBOSE {
	// 	log.Println(response)
	// }

	return &response, nil
}

// Writes back the response to the client, together with its size
func writeResponse(response *bytes.Buffer, conn net.Conn) error {

	defer timeTrack(time.Now(), "writeResponse()")

	err := binary.Write(conn, binary.BigEndian, uint32(len(response.Bytes())))
	if err != nil {
		fmt.Println("Write response length error:", err)
		return err
	}
	log.Printf("Sending back %d bytes (%.3f)", uint32(len(response.Bytes())),
		float64(uint32(len(response.Bytes())))/(1024*1024))

	_, err = conn.Write(response.Bytes())
	if err != nil {
		log.Println("Error writing response", err)
		return err
	}
	log.Println("Result transfered [->]")

	return nil
}

// Starts a simulation and streams the output trace to a redis db
func handleMonitoring(conn net.Conn) {

	defer conn.Close()

	lockServer()
	defer unlockServer()

	// read raw data
	dataLen, rawData, err := getData(context.Background(), conn)
	if err != nil {
		return
	}
	_ = dataLen

	// deserialize data
	rawTrajectory, config, err := prepareRequest(rawData)
	if err != nil {
		log.Println("Invalid simulation request:", err)
		return
	}

	wg := &sync.WaitGroup{}
	wg.Add(1)
	// error channel to get potential error
	errCh := make(chan error, 1)
	defer close(errCh)
	// start monitoring
	go simulator.Start(my_types.Monitoring, config, rawTrajectory, errCh, nil, nil, nil, wg)
	wg.Wait()
	select {
	case err = <-errCh:
		log.Println("Cannot handle monitoring task:", err)
		return
	default:
		log.Println("Monitoring Monitoring ended")
		sendSimulationAck(conn, []byte("Simulation ended"))
	}
}

// Starts a falsification and sends the result back to the client
// todo: compute falsification directly on the server
func handleFalsification(conn net.Conn) {

	defer conn.Close()

	lockServer()
	defer unlockServer()

	// read raw data
	dataLen, rawData, err := getData(context.Background(), conn)
	if err != nil {
		return
	}
	_ = dataLen

	// deserialize data
	rawTrajectory, config, err := prepareRequest(rawData)
	if err != nil {
		log.Println("Invalid simulation request:", err)
		return
	}
	wg := &sync.WaitGroup{}
	wg.Add(1)
	// error channel to get potential error
	errCh := make(chan error, 1)
	defer close(errCh)
	resCh := make(chan my_types.OutputTrace, 1)
	defer close(resCh)
	// start falsification
	// todo: handle falsification on the server
	go simulator.Start(my_types.Falsification, config, rawTrajectory, errCh, resCh, nil, nil, wg)
	wg.Wait()
	// check simulation result
	select {
	case err = <-errCh:
		log.Println("Cannot handle falsification task:", err)
		return
	default:
		// no error, send the output trace to the client
		outTrace := <-resCh
		serializedOutputTrace, err := serialize(outTrace)
		if err != nil {
			log.Printf("Falsification failed: %v", err)
			return
		} else {
			err = writeResponse(serializedOutputTrace, conn)
			if err != nil {
				// log connection write error
				log.Println("Cannot send response to the client")
			}
		}
	}
}

func readStatePerturbationFromNet(ctx context.Context, conn net.Conn, config *my_types.Configuration, ch chan<- []my_types.StateRecord) {

	for {
		// read data from network
		dataLen, rawData, err := getData(ctx, conn)
		if err != nil {
			return
		}
		_ = dataLen
		// deserialize data (contains a vector named "time" to index data points)
		if dataLen == 0 {
			return
		}
		rawPerturbation, err := deserializeState(rawData, config)
		if err != nil {
			log.Println("Invalid state perturbation:", err)
			sendSimulationAck(conn, []byte("ERROR: "+err.Error()))
			return
		}
		// send ack to client
		sendSimulationAck(conn, []byte("Perturbation received correctly"))
		// send data to the injector via channel
		ch <- rawPerturbation
	}
}

func handleStatePerturbation(conn net.Conn) {

	defer conn.Close()

	lockServer()
	defer unlockServer()

	// read the input trace
	dataLen, rawData, err := getData(context.Background(), conn)
	if err != nil {
		return
	}
	_ = dataLen

	// deserialize data
	rawTrajectory, config, err := prepareRequest(rawData)
	if err != nil {
		log.Println("Invalid simulation request:", err)
		return
	}

	// wg for synchronization
	wg := &sync.WaitGroup{}
	wg.Add(1)
	// error channel to get potential error
	errCh := make(chan error, 1)
	defer close(errCh)
	resCh := make(chan my_types.OutputTrace, 1)
	defer close(resCh)
	// create the perturbation communication channel
	statePertCh := make(chan []my_types.StateRecord, 24*512) // 12 KB buffer
	defer close(statePertCh)
	// start the simulation (async)
	go simulator.Start(my_types.StatePerturbation, config, rawTrajectory, errCh, resCh, nil, statePertCh, wg)
	// helper to check simulation ended without blocking
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// start state perturbation network listener
	go readStatePerturbationFromNet(ctx, conn, config, statePertCh)
	// send an ack to the client (so the client can send the state perturbation...)
	sendSimulationAck(conn, []byte("Simulation started"))
simulateAndPerturbState:
	for {
		select {
		case <-done:
			log.Printf("Simulation ended, checking result...")
			break simulateAndPerturbState
		default:
			log.Print("Keep waiting for the end of the simulation")
			// listen and inject data
			time.Sleep(3 * time.Second)
		}
	}
	// check no errors occurred
	select {
	case err = <-errCh:
		log.Println("Error occurred during signal perturbation:", err)
		sendSimulationAck(conn, []byte("ERROR: "+err.Error()))
		return
	default:
		// no error
		log.Println("Simulation finished without errors")
		sendSimulationAck(conn, []byte("Simulation ended without errors"))
		return
	}
}

func deserializeSignalPerturbation(rawData []byte, config *my_types.Configuration) (map[string]interface{}, error) {
	rawPerturbation, err := deserialize(rawData)
	if err != nil {
		return nil, err
	}
	timeValues, ok := rawPerturbation["time"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("signal perturbation requires a time array")
	}
	writable := make(map[string]my_types.Signal)
	for _, group := range config.Writes {
		for _, sig := range group.Signals {
			if sig.Path != "" {
				writable[sig.Path] = sig
			}
			if sig.Name != "" {
				writable[sig.Name] = sig
			}
		}
	}
	normalized := make(map[string]interface{}, len(rawPerturbation))
	normalized["time"] = timeValues
	for key, rawVals := range rawPerturbation {
		if key == "time" {
			continue
		}
		cleanKey, keyErr := sanitizeCatalogPath(key)
		if keyErr != nil {
			return nil, fmt.Errorf("signal perturbation: %w", keyErr)
		}
		sig, matched := writable[cleanKey]
		if !matched {
			return nil, fmt.Errorf("signal perturbation %q is not a configured writable signal", cleanKey)
		}
		vals, ok := rawVals.([]interface{})
		if !ok {
			return nil, fmt.Errorf("signal perturbation %q must be an array of values", cleanKey)
		}
		if len(vals) != len(timeValues) {
			return nil, fmt.Errorf("signal perturbation %q has %d values for %d time values", cleanKey, len(vals), len(timeValues))
		}
		for _, v := range vals {
			if _, err := my_types.EncodeSignalValue(v, sig.Type); err != nil {
				return nil, fmt.Errorf("signal perturbation %q: %w", cleanKey, err)
			}
		}
		canonicalKey := sig.Path
		if canonicalKey == "" {
			canonicalKey = sig.Name
		}
		normalized[canonicalKey] = vals
	}
	return normalized, nil
}

func readPerturbationFromNet(ctx context.Context, conn net.Conn, config *my_types.Configuration, ch chan<- map[string]interface{}) {

	for {
		// read data from network
		dataLen, rawData, err := getData(ctx, conn)
		if err != nil {
			return
		}
		_ = dataLen
		// deserialize data (contains a vector named "time" to index data points)
		if dataLen == 0 {
			return
		}
		rawPerturbation, err := deserializeSignalPerturbation(rawData, config)
		if err != nil {
			log.Println("Invalid signal perturbation:", err)
			sendSimulationAck(conn, []byte("ERROR: "+err.Error()))
			return
		}
		// send ack to client
		sendSimulationAck(conn, []byte("Perturbation received correctly"))
		// send data to the injector via channel
		ch <- rawPerturbation
	}
}

func handleSignalPerturbation(conn net.Conn) {

	defer conn.Close()

	lockServer()
	defer unlockServer()

	// read the input trace
	dataLen, rawData, err := getData(context.Background(), conn)
	if err != nil {
		return
	}
	_ = dataLen

	// deserialize data
	rawTrajectory, config, err := prepareRequest(rawData)
	if err != nil {
		log.Println("Invalid simulation request:", err)
		return
	}

	// wg for synchronization
	wg := &sync.WaitGroup{}
	wg.Add(1)
	// error channel to get potential error
	errCh := make(chan error, 1)
	defer close(errCh)
	resCh := make(chan my_types.OutputTrace, 1)
	defer close(resCh)
	// create the perturbation communication channel
	pertCh := make(chan map[string]interface{}, 1024*1024*64) // 32 MB buffer
	defer close(pertCh)
	// start the simulation (async)
	go simulator.Start(my_types.SignalPerturbation, config, rawTrajectory, errCh, resCh, pertCh, nil, wg)
	// helper to check simulation ended without blocking
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// start perturbation network listener
	go readPerturbationFromNet(ctx, conn, config, pertCh)
	// send perturbation started ack to client (so client can send the perturbation...)
	sendSimulationAck(conn, []byte("Simulation started"))
simulateAndPerturbSignal:
	for {
		select {
		case <-done:
			log.Printf("Simulation ended, checking result...")
			break simulateAndPerturbSignal
		default:
			log.Print("Keep waiting for the end of the simulation")
			// listen and inject data
			time.Sleep(3 * time.Second)
		}
	}
	// check no errors occurred
	select {
	case err = <-errCh:
		log.Println("Error occurred during signal perturbation:", err)
		return
	default:
		// no error
		log.Println("Simulation finished without errors")
		sendSimulationAck(conn, []byte("Simulation ended without errors"))
		return
	}
}

func lockServer() {

	log.Print("Trying to lock the server...")
	BUSY.Lock()
	log.Print("Server locked")
}

func unlockServer() {

	log.Print("Trying to unlock the server...")
	BUSY.Unlock()
	log.Print("Server unlocked")
}

func setReadDeadline(conn net.Conn, seconds uint32) error {

	return conn.SetReadDeadline(time.Now().Add(time.Duration(seconds)))
}

func setWriteDeadline(conn net.Conn, seconds uint32) error {

	return conn.SetWriteDeadline(time.Now().Add(time.Duration(seconds)))
}

func sendSimulationAck(conn net.Conn, msg []byte) {

	maxMsgSize := 64
	paddedMsg := make([]byte, maxMsgSize)
	for p, v := range msg {
		if p > maxMsgSize {
			break
		}
		paddedMsg[p] = v
	}
	_, err := conn.Write(paddedMsg)
	if err != nil {
		log.Print("Error writing response", err)
	}
}
