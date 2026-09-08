package my_types

import (
	"fmt"
	"math"
)

// SignalType is the fixed ABI used by configuration, userspace, and eBPF.
type SignalType uint32

const (
	SignalBool SignalType = iota + 1
	SignalInt8
	SignalInt16
	SignalInt32
	SignalInt64
	SignalUint8
	SignalUint16
	SignalUint32
	SignalUint64
	SignalFloat32
	SignalFloat64
)

type SignalTypeInfo struct {
	Code SignalType
	Name string
	Size uint32
}

var signalTypeInfo = map[string]SignalTypeInfo{
	"bool": {SignalBool, "bool", 1}, "int8": {SignalInt8, "int8", 1}, "int16": {SignalInt16, "int16", 2},
	"int32": {SignalInt32, "int32", 4}, "int64": {SignalInt64, "int64", 8}, "uint8": {SignalUint8, "uint8", 1},
	"uint16": {SignalUint16, "uint16", 2}, "uint32": {SignalUint32, "uint32", 4}, "uint64": {SignalUint64, "uint64", 8},
	"float32": {SignalFloat32, "float32", 4}, "float64": {SignalFloat64, "float64", 8},
}

func ParseSignalType(name string) (SignalTypeInfo, error) {
	info, ok := signalTypeInfo[name]
	if !ok {
		return SignalTypeInfo{}, fmt.Errorf("unsupported signal type %q", name)
	}
	return info, nil
}

// EncodeSignalValue converts a decoded MessagePack scalar to its native memory
// representation. Values are retained as bits so they can cross the eBPF ABI
// without being coerced to float64.
func EncodeSignalValue(value any, typ string) (uint64, error) {
	info, err := ParseSignalType(typ)
	if err != nil {
		return 0, err
	}
	number, ok := scalarNumber(value)
	if typ == "bool" {
		if b, ok := value.(bool); ok {
			if b {
				return 1, nil
			}
			return 0, nil
		}
		if ok && (number == 0 || number == 1) {
			return uint64(number), nil
		}
		return 0, fmt.Errorf("%s value must be boolean", typ)
	}
	// Preserve integer values supplied by a typed MessagePack client; routing
	// them through float64 would lose uint64 precision above 2^53.
	if i, u, signed, ok := scalarInteger(value); ok {
		switch info.Code {
		case SignalInt8:
			if signed {
				return uint64(uint8(int8(i))), nil
			}
			return uint64(uint8(int8(u))), nil
		case SignalInt16:
			if signed {
				return uint64(uint16(int16(i))), nil
			}
			return uint64(uint16(int16(u))), nil
		case SignalInt32:
			if signed {
				return uint64(uint32(int32(i))), nil
			}
			return uint64(uint32(int32(u))), nil
		case SignalInt64:
			if signed {
				return uint64(i), nil
			}
			return uint64(int64(u)), nil
		case SignalUint8:
			return uint64(uint8(u)), nil
		case SignalUint16:
			return uint64(uint16(u)), nil
		case SignalUint32:
			return uint64(uint32(u)), nil
		case SignalUint64:
			return u, nil
		}
	}
	if !ok {
		return 0, fmt.Errorf("%s value must be numeric", typ)
	}
	switch info.Code {
	case SignalInt8:
		return uint64(uint8(int8(number))), nil
	case SignalInt16:
		return uint64(uint16(int16(number))), nil
	case SignalInt32:
		return uint64(uint32(int32(number))), nil
	case SignalInt64:
		return uint64(int64(number)), nil
	case SignalUint8:
		return uint64(uint8(number)), nil
	case SignalUint16:
		return uint64(uint16(number)), nil
	case SignalUint32:
		return uint64(uint32(number)), nil
	case SignalUint64:
		return uint64(number), nil
	case SignalFloat32:
		return uint64(math.Float32bits(float32(number))), nil
	case SignalFloat64:
		return math.Float64bits(number), nil
	}
	return 0, fmt.Errorf("unsupported signal type %q", typ)
}

func scalarInteger(value any) (int64, uint64, bool, bool) {
	switch v := value.(type) {
	case int:
		return int64(v), uint64(v), true, true
	case int8:
		return int64(v), uint64(v), true, true
	case int16:
		return int64(v), uint64(v), true, true
	case int32:
		return int64(v), uint64(v), true, true
	case int64:
		return v, uint64(v), true, true
	case uint:
		return int64(v), uint64(v), false, true
	case uint8:
		return int64(v), uint64(v), false, true
	case uint16:
		return int64(v), uint64(v), false, true
	case uint32:
		return int64(v), uint64(v), false, true
	case uint64:
		return int64(v), v, false, true
	default:
		return 0, 0, false, false
	}
}

func scalarNumber(value any) (float64, bool) {
	switch v := value.(type) {
	case float64:
		return v, true
	case float32:
		return float64(v), true
	case int:
		return float64(v), true
	case int8:
		return float64(v), true
	case int16:
		return float64(v), true
	case int32:
		return float64(v), true
	case int64:
		return float64(v), true
	case uint:
		return float64(v), true
	case uint8:
		return float64(v), true
	case uint16:
		return float64(v), true
	case uint32:
		return float64(v), true
	case uint64:
		return float64(v), true
	default:
		return 0, false
	}
}

func DecodeSignalValue(bits uint64, typ string) (any, error) {
	info, err := ParseSignalType(typ)
	if err != nil {
		return nil, err
	}
	switch info.Code {
	case SignalBool:
		return bits&1 != 0, nil
	case SignalInt8:
		return int8(bits), nil
	case SignalInt16:
		return int16(bits), nil
	case SignalInt32:
		return int32(bits), nil
	case SignalInt64:
		return int64(bits), nil
	case SignalUint8:
		return uint8(bits), nil
	case SignalUint16:
		return uint16(bits), nil
	case SignalUint32:
		return uint32(bits), nil
	case SignalUint64:
		return bits, nil
	case SignalFloat32:
		return math.Float32frombits(uint32(bits)), nil
	case SignalFloat64:
		return math.Float64frombits(bits), nil
	}
	return nil, fmt.Errorf("unsupported signal type %q", typ)
}
