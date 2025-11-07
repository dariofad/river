package server

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/dariofad/ebpf_simulator/my_types"
	"github.com/dariofad/ebpf_simulator/simulator"
	"github.com/vmihailenco/msgpack/v5"
)

var VERBOSE bool
var SERVER_BUSY sync.Mutex

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
			log.Print("%s server accepted connection, %s", srv.String(), err)
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
	fmt.Printf("|__func %s took %.3f ms\n", name, float64(elapsed.Nanoseconds())/1e6)
}

// Reads the connection incoming data. Returns the received data
// length (in bytes), and the related byte array
func getData(conn net.Conn) (uint32, []byte, error) {

	defer timeTrack(time.Now(), "getData()")

	// get the data length (expected to be a uint32)
	var dataLenBuf [4]byte
	n, err := conn.Read(dataLenBuf[:])
	if err != nil || n != 4 {
		log.Println("Data length read error:",
			err,
			"bytes read:",
			n)
		return 0, nil, err
	}
	dataLen := binary.BigEndian.Uint32(dataLenBuf[:])
	if VERBOSE {
		log.Println("DataLenBuf:", dataLenBuf)
	}
	log.Printf("Receiving %d bytes (%.3f MB)", dataLen, float64(dataLen)/(1024*1024))

	// get the data
	var rawData []byte
	chunk := make([]byte, 16384)
	for len(rawData) != int(dataLen) {
		n, err := conn.Read(chunk)
		rawData = append(rawData, chunk[:n]...)
		if err != nil {
			log.Println("Chunk reading error:", err)
			return dataLen, nil, err
		}
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
	dataLen, rawData, err := getData(conn)
	if err != nil {
		return
	}
	_ = dataLen

	// deserialize data
	rawTrajectory, err := deserialize(rawData)
	if err != nil {
		return
	}

	// start non-interactive monitoring
	_, err = simulator.Start(my_types.Monitoring, rawTrajectory)
	if err != nil {
		log.Println("Cannot handle monitoring task:", err)
		return
	} else {
		log.Println("Monitoring started")
		sendSimulationStartedAck(conn)
	}
}

// Starts a falsification and sends the result back to the client
func handleFalsification(conn net.Conn) {

	defer conn.Close()

	lockServer()
	defer unlockServer()

	// read raw data
	dataLen, rawData, err := getData(conn)
	if err != nil {
		return
	}
	_ = dataLen

	// deserialize data
	rawTrajectory, err := deserialize(rawData)
	if err != nil {
		return
	}

	// start non-interactive falsification
	outTrace, err := simulator.Start(my_types.Falsification, rawTrajectory)
	if err != nil {
		log.Println("Cannot handle falsification task:", err)
		return
	} else {
		log.Println("Falsification started")
		serializedOutputTrace, err := serialize(*outTrace)
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

// todo: implement
func handleStatePerturbation(conn net.Conn) {

	defer conn.Close()
	lockServer()
	defer unlockServer()
}

// todo: implement
func handleSignalPerturbation(conn net.Conn) {

	defer conn.Close()
	lockServer()
	defer unlockServer()
}

func lockServer() {

	log.Print("Trying to lock the server...")
	SERVER_BUSY.Lock()
	log.Print("Server locked")
}

func unlockServer() {

	log.Print("Trying to unlock the server...")
	SERVER_BUSY.Unlock()
	log.Print("Server unlocked")
}

func setReadDeadline(conn net.Conn, seconds uint32) error {

	return conn.SetReadDeadline(time.Now().Add(time.Duration(seconds)))
}

func setWriteDeadline(conn net.Conn, seconds uint32) error {

	return conn.SetWriteDeadline(time.Now().Add(time.Duration(seconds)))
}

func sendSimulationStartedAck(conn net.Conn) {

	_, err := conn.Write([]byte("Simulation correctly started"))
	if err != nil {
		log.Print("Error writing response", err)
	}
}
