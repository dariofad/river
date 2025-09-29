package simulator

import "strconv"

// mock result struct
type Result struct {
	AEgo []float64 `msgpack:"a_ego"`
	VEgo []float64 `msgpack:"v_ego"`
}

type ModelRecord struct {
	Time   uint32
	Filler uint32
	AEgo   float64
	VEgo   float64
}

func ModelRecordToCSVString(record ModelRecord) string {
	return strconv.Itoa(int(record.Time)) +
		"," + strconv.FormatFloat(record.AEgo, 'f', 5, 64) +
		"," + strconv.FormatFloat(record.VEgo, 'f', 5, 64)
}
