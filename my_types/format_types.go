package my_types

type Signal struct {
	SignName string `json:"SIGN_NAME"`
	SignType string `json:"SIGN_TYPE"`
	SignAddr string `json:"SIGN_ADDR"`
}

type SignTiming struct {
	SymbolName string   `json:"SYMBOL"`
	Offset     string   `json:"OFFSET"`
	Signals    []Signal `json:"SIGNALS"`
}

type SimFormat struct {
	ModelPath         string     `json:"MODEL_PATH"`
	TimerSymbol       string     `json:"TIMER_SYMBOL"`
	MinorToMajorRatio string     `json:"MINOR_TO_MAJOR_RATIO"`
	NofCycles         string     `json:"NOF_CYCLES"`
	WTimingI          SignTiming `json:"WRITE_TIMING_I"`
	RTimingI          SignTiming `json:"READ_TIMING_I"`
	RTimingO          SignTiming `json:"READ_TIMING_O"`
}
