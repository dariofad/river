package my_types

type Signal struct {
	Name string `json:"NAME"`
	Type string `json:"TYPE"`
	Addr string `json:"ADDR"`
}

type Group struct {
	Symbol  string   `json:"SYMBOL"`
	Offset  string   `json:"OFFSET"`
	Signals []Signal `json:"SIGNALS"`
}

type Configuration struct {
	ModelPath         string  `json:"MODEL_PATH"`
	TimerSymbol       string  `json:"TIMER_SYMBOL"`
	MinorToMajorRatio string  `json:"MINOR_TO_MAJOR_RATIO"`
	NofCycles         string  `json:"NOF_CYCLES"`
	Reads             []Group `json:"READS"`
	Writes            []Group `json:"WRITES"`
}
