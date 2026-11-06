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
		return nil, nil, my_types.NewSimulationErrorf(my_types.ErrCategoryRequest, "decode simulation request: %w", err)
	}
	if request.Manifest == "" || request.Trajectory == nil {
		return nil, nil, my_types.NewSimulationErrorf(my_types.ErrCategoryRequest, "simulation request requires manifest YAML and a trajectory map")
	}
	var m manifest.Manifest
	if err := yaml.Unmarshal([]byte(request.Manifest), &m); err != nil {
		return nil, nil, my_types.NewSimulationErrorf(my_types.ErrCategoryManifest, "parse manifest: %w", err)
	}
	config, err := manifest.CompileConfiguration(&m)
	if err != nil {
		return nil, nil, my_types.NewSimulationError(my_types.ErrCategoryManifest, err)
	}
	sanitizedTrajectory := make(map[string]interface{}, len(request.Trajectory))
	for key, values := range request.Trajectory {
		cleanKey, keyErr := sanitizeCatalogPath(key)
		if keyErr != nil {
			return nil, nil, my_types.NewSimulationErrorf(my_types.ErrCategoryTrajectory, "trajectory key: %w", keyErr)
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
		return nil, my_types.NewSimulationErrorf(my_types.ErrCategoryPerturbation, "decode state perturbation: %w", err)
	}
	cycles, _ := strconv.ParseUint(config.NofCycles, 10, 32)
	for i := range data {
		record := &data[i]
		if cycles > 0 && uint64(record.Time) >= cycles {
			return nil, my_types.NewSimulationErrorf(my_types.ErrCategoryPerturbation, "state perturbation time %d is out of range (cycles: %d)", record.Time, cycles)
		}
		if strings.TrimSpace(record.Name) != "" {
			cleanPath, pathErr := sanitizeCatalogPath(record.Name)
			if pathErr != nil {
				return nil, my_types.NewSimulationErrorf(my_types.ErrCategoryPerturbation, "state perturbation: %w", pathErr)
			}
			entry, ok := config.Catalog[cleanPath]
			if !ok {
				return nil, my_types.NewSimulationErrorf(my_types.ErrCategoryPerturbation, "state perturbation %q is not a writable entry in the manifest catalog", cleanPath)
			}
			catalogAddr, parseErr := strconv.ParseUint(entry.Addr, 0, 64)
			if parseErr != nil {
				return nil, my_types.NewSimulationErrorf(my_types.ErrCategoryPerturbation, "state perturbation %q has invalid catalog address %q: %w", cleanPath, entry.Addr, parseErr)
			}
			if record.Addr != 0 && record.Addr != catalogAddr {
				return nil, my_types.NewSimulationErrorf(my_types.ErrCategoryPerturbation, "state perturbation %q specifies address %#x, which does not match catalog address %#x", cleanPath, record.Addr, catalogAddr)
			}
			record.Addr = catalogAddr
			record.Name = cleanPath
			if record.Type == "" {
				record.Type = entry.Type
			} else if record.Type != entry.Type {
				return nil, my_types.NewSimulationErrorf(my_types.ErrCategoryPerturbation, "state perturbation %q has TYPE %q; catalog requires %q", cleanPath, record.Type, entry.Type)
			}
			info, typeErr := my_types.ParseSignalType(record.Type)
			if typeErr != nil {
				return nil, my_types.NewSimulationErrorf(my_types.ErrCategoryPerturbation, "state perturbation %q: %w", cleanPath, typeErr)
			}
			if record.ValueSize == 0 {
				record.ValueSize = info.Size
			} else if record.ValueSize != info.Size {
				return nil, my_types.NewSimulationErrorf(my_types.ErrCategoryPerturbation, "state perturbation %q has VALUE_SIZE %d; %s requires %d", cleanPath, record.ValueSize, record.Type, info.Size)
			}
			if _, typeErr = my_types.EncodeSignalValue(record.Value, record.Type); typeErr != nil {
				return nil, my_types.NewSimulationErrorf(my_types.ErrCategoryPerturbation, "state perturbation %q: %w", cleanPath, typeErr)
			}
		} else {
			if record.Addr == 0 {
				return nil, my_types.NewSimulationErrorf(my_types.ErrCategoryPerturbation, "state perturbation requires either NAME (catalog path) or ADDR")
			}
			info, typeErr := my_types.ParseSignalType(record.Type)
			if typeErr != nil {
				return nil, my_types.NewSimulationErrorf(my_types.ErrCategoryPerturbation, "state perturbation at %#x: %w", record.Addr, typeErr)
			}
			if record.ValueSize != info.Size {
				return nil, my_types.NewSimulationErrorf(my_types.ErrCategoryPerturbation, "state perturbation at %#x has VALUE_SIZE %d; %s requires %d", record.Addr, record.ValueSize, record.Type, info.Size)
			}
			if _, typeErr = my_types.EncodeSignalValue(record.Value, record.Type); typeErr != nil {
				return nil, my_types.NewSimulationErrorf(my_types.ErrCategoryPerturbation, "state perturbation at %#x: %w", record.Addr, typeErr)
			}
		}
	}
	log.Println("State Data deserialized")
	if VERBOSE {
		log.Println(data)
	}

	return data, nil

}

// Serializes a ServerResponse using MessagePack
func serializeResponse(resp my_types.ServerResponse) (*bytes.Buffer, error) {

	defer timeTrack(time.Now(), "serializeResponse()")

	var response bytes.Buffer
	enc := msgpack.NewEncoder(&response)
	if err := enc.Encode(resp); err != nil {
		log.Println("Response encode error:", err)
		return nil, err
	}
	return &response, nil
}

// Writes back the length-prefixed MessagePack response to the client
func writeResponse(response *bytes.Buffer, conn net.Conn) error {

	defer timeTrack(time.Now(), "writeResponse()")

	err := binary.Write(conn, binary.BigEndian, uint32(len(response.Bytes())))
	if err != nil {
		log.Println("Write response length error:", err)
		return err
	}
	log.Printf("Sending back %d bytes (%.3f MB)", uint32(len(response.Bytes())),
		float64(uint32(len(response.Bytes())))/(1024*1024))

	_, err = conn.Write(response.Bytes())
	if err != nil {
		log.Println("Error writing response", err)
		return err
	}
	log.Println("Response transferred [->]")

	return nil
}

func sendResponse(conn net.Conn, resp my_types.ServerResponse) error {
	buf, err := serializeResponse(resp)
	if err != nil {
		return err
	}
	return writeResponse(buf, conn)
}

func sendErrorResponse(ctx context.Context, conn net.Conn, mode my_types.Service, err error, fallbackCategory my_types.ErrorCategory) {
	category, message := my_types.CategorizeError(err, fallbackCategory)
	_ = simulator.UpdateRedisStatus(ctx, mode, my_types.StatusError, category, message)
	_ = sendResponse(conn, my_types.ServerResponse{
		Status:   my_types.StatusError,
		Category: category,
		Message:  message,
	})
}

func receiveInitialRequest(ctx context.Context, conn net.Conn, mode my_types.Service) (map[string]interface{}, *my_types.Configuration, bool) {
	// Reset previous simulation state and errors in Redis.
	// In Falsification mode, Redis is optional for results, so do not fail the request if Redis is unreachable.
	if err := simulator.ResetRedisSimulation(ctx, mode); err != nil && mode != my_types.Falsification {
		log.Println("Cannot reset Redis simulation state:", err)
		sendErrorResponse(ctx, conn, mode, err, my_types.ErrCategoryRedis)
		return nil, nil, false
	}

	_, rawData, err := getData(ctx, conn)
	if err != nil {
		return nil, nil, false
	}

	rawTrajectory, config, err := prepareRequest(rawData)
	if err != nil {
		log.Println("Invalid simulation request:", err)
		sendErrorResponse(ctx, conn, mode, err, my_types.ErrCategoryManifest)
		return nil, nil, false
	}
	return rawTrajectory, config, true
}

func waitForSimulationStart(ctx context.Context, conn net.Conn, mode my_types.Service, readyCh <-chan struct{}, errCh <-chan error, done <-chan struct{}) (error, bool) {
	select {
	case <-readyCh:
		_ = simulator.UpdateRedisStatus(ctx, mode, my_types.StatusRunning, my_types.ErrCategoryNone, "Simulation is running")
		if err := sendResponse(conn, my_types.ServerResponse{
			Status:  my_types.StatusStarted,
			Message: "Simulation started",
		}); err != nil {
			return err, false
		}
		return nil, true
	case err := <-errCh:
		<-done
		log.Printf("Cannot start %s simulation: %v", mode.String(), err)
		sendErrorResponse(ctx, conn, mode, err, my_types.ErrCategoryEBPF)
		return err, false
	}
}

// Starts a simulation and streams the output trace to a redis db
func handleMonitoring(conn net.Conn) {

	defer conn.Close()

	lockServer()
	defer unlockServer()

	ctx := context.Background()
	rawTrajectory, config, ok := receiveInitialRequest(ctx, conn, my_types.Monitoring)
	if !ok {
		return
	}

	wg := &sync.WaitGroup{}
	wg.Add(1)
	readyCh := make(chan struct{})
	errCh := make(chan error, 1)
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	go simulator.Start(my_types.Monitoring, config, rawTrajectory, readyCh, errCh, nil, nil, nil, wg)
	if _, started := waitForSimulationStart(ctx, conn, my_types.Monitoring, readyCh, errCh, done); !started {
		return
	}

	<-done
	select {
	case err := <-errCh:
		log.Println("Cannot handle monitoring task:", err)
		sendErrorResponse(ctx, conn, my_types.Monitoring, err, my_types.ErrCategoryTarget)
	default:
		log.Println("Monitoring ended")
		_ = simulator.UpdateRedisStatus(ctx, my_types.Monitoring, my_types.StatusCompleted, my_types.ErrCategoryNone, "Simulation ended")
		_ = sendResponse(conn, my_types.ServerResponse{
			Status:  my_types.StatusCompleted,
			Message: "Simulation ended",
		})
	}
}

// Starts a falsification and sends the result back to the client
func handleFalsification(conn net.Conn) {

	defer conn.Close()

	lockServer()
	defer unlockServer()

	ctx := context.Background()
	rawTrajectory, config, ok := receiveInitialRequest(ctx, conn, my_types.Falsification)
	if !ok {
		return
	}

	wg := &sync.WaitGroup{}
	wg.Add(1)
	readyCh := make(chan struct{})
	errCh := make(chan error, 1)
	resCh := make(chan my_types.OutputTrace, 1)
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	go simulator.Start(my_types.Falsification, config, rawTrajectory, readyCh, errCh, resCh, nil, nil, wg)
	if _, started := waitForSimulationStart(ctx, conn, my_types.Falsification, readyCh, errCh, done); !started {
		return
	}

	<-done
	select {
	case err := <-errCh:
		log.Println("Cannot handle falsification task:", err)
		sendErrorResponse(ctx, conn, my_types.Falsification, err, my_types.ErrCategoryTarget)
	default:
		outTrace := <-resCh
		_ = simulator.UpdateRedisStatus(ctx, my_types.Falsification, my_types.StatusCompleted, my_types.ErrCategoryNone, "Falsification completed")
		if err := sendResponse(conn, my_types.ServerResponse{
			Status:     my_types.StatusCompleted,
			Message:    "Falsification completed",
			OutSignals: outTrace.Signals,
		}); err != nil {
			log.Println("Cannot send response to the client:", err)
		}
	}
}

func readStatePerturbationFromNet(ctx context.Context, conn net.Conn, config *my_types.Configuration, ch chan<- []my_types.StateRecord) {

	for {
		dataLen, rawData, err := getData(ctx, conn)
		if err != nil || dataLen == 0 {
			return
		}
		rawPerturbation, err := deserializeState(rawData, config)
		if err != nil {
			log.Println("Invalid state perturbation:", err)
			sendErrorResponse(ctx, conn, my_types.StatePerturbation, err, my_types.ErrCategoryPerturbation)
			return
		}
		if err := sendResponse(conn, my_types.ServerResponse{
			Status:  my_types.StatusAck,
			Message: "Perturbation received correctly",
		}); err != nil {
			return
		}
		select {
		case ch <- rawPerturbation:
		case <-ctx.Done():
			return
		}
	}
}

func handleStatePerturbation(conn net.Conn) {

	defer conn.Close()

	lockServer()
	defer unlockServer()

	baseCtx := context.Background()
	rawTrajectory, config, ok := receiveInitialRequest(baseCtx, conn, my_types.StatePerturbation)
	if !ok {
		return
	}

	wg := &sync.WaitGroup{}
	wg.Add(1)
	readyCh := make(chan struct{})
	errCh := make(chan error, 1)
	resCh := make(chan my_types.OutputTrace, 1)
	statePertCh := make(chan []my_types.StateRecord, 24*512)
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	go simulator.Start(my_types.StatePerturbation, config, rawTrajectory, readyCh, errCh, resCh, nil, statePertCh, wg)
	if _, started := waitForSimulationStart(baseCtx, conn, my_types.StatePerturbation, readyCh, errCh, done); !started {
		return
	}

	ctx, cancel := context.WithCancel(baseCtx)
	defer cancel()
	go readStatePerturbationFromNet(ctx, conn, config, statePertCh)

	<-done
	log.Printf("Simulation ended, checking result...")

	select {
	case err := <-errCh:
		log.Println("Error occurred during state perturbation:", err)
		sendErrorResponse(baseCtx, conn, my_types.StatePerturbation, err, my_types.ErrCategoryPerturbation)
	default:
		log.Println("Simulation finished without errors")
		_ = simulator.UpdateRedisStatus(baseCtx, my_types.StatePerturbation, my_types.StatusCompleted, my_types.ErrCategoryNone, "Simulation ended without errors")
		_ = sendResponse(conn, my_types.ServerResponse{
			Status:  my_types.StatusCompleted,
			Message: "Simulation ended without errors",
		})
	}
}

func deserializeSignalPerturbation(rawData []byte, config *my_types.Configuration) (map[string]interface{}, error) {
	rawPerturbation, err := deserialize(rawData)
	if err != nil {
		return nil, my_types.NewSimulationErrorf(my_types.ErrCategoryPerturbation, "decode signal perturbation: %w", err)
	}
	timeValues, ok := rawPerturbation["time"].([]interface{})
	if !ok {
		return nil, my_types.NewSimulationErrorf(my_types.ErrCategoryPerturbation, "signal perturbation requires a time array")
	}
	cycles, _ := strconv.ParseUint(config.NofCycles, 10, 32)
	for _, rawTimeVal := range timeValues {
		tVal, valid := customTimeVal(rawTimeVal)
		if !valid {
			return nil, my_types.NewSimulationErrorf(my_types.ErrCategoryPerturbation, "signal perturbation time value %v is not a valid non-negative integer", rawTimeVal)
		}
		if cycles > 0 && uint64(tVal) >= cycles {
			return nil, my_types.NewSimulationErrorf(my_types.ErrCategoryPerturbation, "signal perturbation time %d is out of range (cycles: %d)", tVal, cycles)
		}
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
			return nil, my_types.NewSimulationErrorf(my_types.ErrCategoryPerturbation, "signal perturbation: %w", keyErr)
		}
		sig, matched := writable[cleanKey]
		if !matched {
			return nil, my_types.NewSimulationErrorf(my_types.ErrCategoryPerturbation, "signal perturbation %q is not a configured writable signal", cleanKey)
		}
		vals, ok := rawVals.([]interface{})
		if !ok {
			return nil, my_types.NewSimulationErrorf(my_types.ErrCategoryPerturbation, "signal perturbation %q must be an array of values", cleanKey)
		}
		if len(vals) != len(timeValues) {
			return nil, my_types.NewSimulationErrorf(my_types.ErrCategoryPerturbation, "signal perturbation %q has %d values for %d time values", cleanKey, len(vals), len(timeValues))
		}
		for _, v := range vals {
			if _, err := my_types.EncodeSignalValue(v, sig.Type); err != nil {
				return nil, my_types.NewSimulationErrorf(my_types.ErrCategoryPerturbation, "signal perturbation %q: %w", cleanKey, err)
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

func customTimeVal(rawVal interface{}) (uint32, bool) {
	switch v := rawVal.(type) {
	case uint8:
		return uint32(v), true
	case uint16:
		return uint32(v), true
	case uint32:
		return v, true
	case uint64:
		return uint32(v), true
	case int8:
		if v < 0 {
			return 0, false
		}
		return uint32(v), true
	case int16:
		if v < 0 {
			return 0, false
		}
		return uint32(v), true
	case int32:
		if v < 0 {
			return 0, false
		}
		return uint32(v), true
	case int64:
		if v < 0 {
			return 0, false
		}
		return uint32(v), true
	case int:
		if v < 0 {
			return 0, false
		}
		return uint32(v), true
	default:
		return 0, false
	}
}

func readPerturbationFromNet(ctx context.Context, conn net.Conn, config *my_types.Configuration, ch chan<- map[string]interface{}) {

	for {
		dataLen, rawData, err := getData(ctx, conn)
		if err != nil || dataLen == 0 {
			return
		}
		rawPerturbation, err := deserializeSignalPerturbation(rawData, config)
		if err != nil {
			log.Println("Invalid signal perturbation:", err)
			sendErrorResponse(ctx, conn, my_types.SignalPerturbation, err, my_types.ErrCategoryPerturbation)
			return
		}
		if err := sendResponse(conn, my_types.ServerResponse{
			Status:  my_types.StatusAck,
			Message: "Perturbation received correctly",
		}); err != nil {
			return
		}
		select {
		case ch <- rawPerturbation:
		case <-ctx.Done():
			return
		}
	}
}

func handleSignalPerturbation(conn net.Conn) {

	defer conn.Close()

	lockServer()
	defer unlockServer()

	baseCtx := context.Background()
	rawTrajectory, config, ok := receiveInitialRequest(baseCtx, conn, my_types.SignalPerturbation)
	if !ok {
		return
	}

	wg := &sync.WaitGroup{}
	wg.Add(1)
	readyCh := make(chan struct{})
	errCh := make(chan error, 1)
	resCh := make(chan my_types.OutputTrace, 1)
	pertCh := make(chan map[string]interface{}, 1024)
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	go simulator.Start(my_types.SignalPerturbation, config, rawTrajectory, readyCh, errCh, resCh, pertCh, nil, wg)
	if _, started := waitForSimulationStart(baseCtx, conn, my_types.SignalPerturbation, readyCh, errCh, done); !started {
		return
	}

	ctx, cancel := context.WithCancel(baseCtx)
	defer cancel()
	go readPerturbationFromNet(ctx, conn, config, pertCh)

	<-done
	log.Printf("Simulation ended, checking result...")

	select {
	case err := <-errCh:
		log.Println("Error occurred during signal perturbation:", err)
		sendErrorResponse(baseCtx, conn, my_types.SignalPerturbation, err, my_types.ErrCategoryPerturbation)
	default:
		log.Println("Simulation finished without errors")
		_ = simulator.UpdateRedisStatus(baseCtx, my_types.SignalPerturbation, my_types.StatusCompleted, my_types.ErrCategoryNone, "Simulation ended without errors")
		_ = sendResponse(conn, my_types.ServerResponse{
			Status:  my_types.StatusCompleted,
			Message: "Simulation ended without errors",
		})
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
