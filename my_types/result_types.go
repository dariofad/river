package my_types

type ModelRecord struct {
	Time   uint32
	Filler uint32
	Values []uint64
}

type StateRecord struct {
	Time      uint32 `msgpack:"TIME"`
	ValueSize uint32 `msgpack:"VALUE_SIZE"`
	// Addr is a virtual address in the target ELF image, not a runtime address.
	Addr  uint64 `msgpack:"ADDR"`
	Type  string `msgpack:"TYPE"`
	Value any    `msgpack:"VALUE"`
}

type Trace struct {
	SignName string `msgpack:"NAME"`
	Type     string `msgpack:"TYPE"`
	Values   []any  `msgpack:"VALUES"`
}

// generalized output trace
type OutputTrace struct {
	Signals []Trace `msgpack:"OUT_SIGNALS"`
}
