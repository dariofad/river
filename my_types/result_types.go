package my_types

import (
	"bytes"
	"strconv"
)

type OutRecord struct {
	Time   uint32
	Filler uint32
	Values []float64
}

func ModelRecordToCSVString(record OutRecord) string {

	var tmp bytes.Buffer
	tmp.WriteString(strconv.Itoa(int(record.Time)))
	for _, v := range record.Values {
		tmp.WriteString(",")
		tmp.WriteString(strconv.FormatFloat(v, 'f', 7, 64))
	}
	return tmp.String()
}

type Trace struct {
	SignName string    `msgpack:"SIGN_NAME"`
	Values   []float64 `msgpack:"VALUES"`
}

// generalized output trace
type OutputTrace struct {
	Signals []Trace `msgpack:"OUT_SIGNALS"`
}
