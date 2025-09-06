package server

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strconv"
	"time"

	"github.com/dariofad/ebpf_simulator/simulator"
	"github.com/vmihailenco/msgpack/v5"
)

// mock result struct
type Result struct {
	Y    []float64 `msgpack:"Y"`
	YErr []float64 `msgpack:"YError"`
}

var VERBOSE bool

func StartServer(port uint16) {

	// start tcp server
	listener, err := net.Listen("tcp", ":"+strconv.Itoa(int(port)))
	if err != nil {
		log.Fatal("Server cannot setup the listener")
	}
	defer listener.Close()
	log.Println("Server Listening on port", strconv.Itoa(int(port)))

	// handle connections
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Print("Error accepting connection", err)
			continue
		}
		log.Println("[->] Connection accepted")

		go handleConnection(conn)
	}
}

// todo implement
func StopServer() {
	// todo evaluate changes to the StartServer function
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
func serialize(result Result) (*bytes.Buffer, error) {

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

func handleConnection(conn net.Conn) {

	defer conn.Close()
	transferDuration := 15 * time.Second

	// set read deadline
	err := conn.SetReadDeadline(time.Now().Add(transferDuration))
	if err != nil {
		log.Println("ReadDeadline set error:", err)
		return
	}

	// read raw data
	dataLen, rawData, err := getData(conn)
	if err != nil {
		return
	}
	_ = dataLen

	// deserialize data
	data, err := deserialize(rawData)
	if err != nil {
		return
	}
	_ = data

	// ... RUN THE SIMULATION WITH eBPF HERE...
	go simulator.Run(data)

	// create a mock result
	result := Result{
		Y:    make([]float64, 10),
		YErr: []float64{0.001, -0.35},
	}
	log.Println("Mock result created")
	if VERBOSE {
		log.Println(result)
	}

	// serialize result
	response, err := serialize(result)
	if err != nil {
		return
	}

	// set write deadline
	err = conn.SetWriteDeadline(time.Now().Add(transferDuration))
	if err != nil {
		log.Println("WriteDeadline set error:", err)
		return
	}

	// write the response
	err = writeResponse(response, conn)
	_ = err
}
