package my_types

import (
	"bytes"
	"strconv"
)

type ModelRecord struct {
	Time   uint32
	Filler uint32
	Values []float64
}

type StateRecord struct {
	Time      uint32  `msgpack:"TIME"`
	ValueSize uint32  `msgpack:"VALUE_SIZE"`
	Addr      uint64  `msgpack:"ADDR"`
	Value     float64 `msgpack:"VALUE"`
}

func ModelRecordToCSVString(record ModelRecord) string {

	var tmp bytes.Buffer
	tmp.WriteString(strconv.Itoa(int(record.Time)))
	for _, v := range record.Values {
		tmp.WriteString(",")
		tmp.WriteString(strconv.FormatFloat(v, 'f', 7, 64))
	}
	return tmp.String()
}

type Trace struct {
	SignName string    `msgpack:"NAME"`
	Values   []float64 `msgpack:"VALUES"`
}

// generalized output trace
type OutputTrace struct {
	Signals []Trace `msgpack:"OUT_SIGNALS"`
}
