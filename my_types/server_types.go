package my_types

import (
	"errors"
	"fmt"
)

type Service int

const (
	Monitoring Service = iota
	Falsification
	StatePerturbation
	SignalPerturbation
)

func (srv Service) String() string {
	return [...]string{"monitoring", "falsification", "state_perturbation", "signal_perturbation"}[srv]
}

func StringToService(srvName string) Service {

	switch srvName {
	case "monitoring":
		return Monitoring
	case "falsification":
		return Falsification
	case "state_perturbation":
		return StatePerturbation
	case "signal_perturbation":
		return SignalPerturbation
	}
	// default value
	return Monitoring
}

type ServerStatus string

const (
	StatusStarting  ServerStatus = "starting"
	StatusStarted   ServerStatus = "started"
	StatusRunning   ServerStatus = "running"
	StatusAck       ServerStatus = "ack"
	StatusCompleted ServerStatus = "completed"
	StatusError     ServerStatus = "error"
)

type ErrorCategory string

const (
	ErrCategoryNone         ErrorCategory = ""
	ErrCategoryRequest      ErrorCategory = "request_error"
	ErrCategoryManifest     ErrorCategory = "manifest_error"
	ErrCategoryTrajectory   ErrorCategory = "trajectory_error"
	ErrCategoryPerturbation ErrorCategory = "perturbation_error"
	ErrCategoryEBPF         ErrorCategory = "ebpf_error"
	ErrCategoryTarget       ErrorCategory = "target_error"
	ErrCategoryRedis        ErrorCategory = "redis_error"
)

// ServerResponse is the unified MessagePack payload sent by the server to the client.
type ServerResponse struct {
	Status     ServerStatus  `msgpack:"status"`
	Category   ErrorCategory `msgpack:"category,omitempty"`
	Message    string        `msgpack:"message,omitempty"`
	OutSignals []Trace       `msgpack:"OUT_SIGNALS,omitempty"`
}

// SimulationStatus is stored in Redis under simulation:0:status to expose live
// simulation state and errors to external consumers (such as the dashboard).
type SimulationStatus struct {
	Status    ServerStatus  `msgpack:"status"`
	Mode      string        `msgpack:"mode"`
	Category  ErrorCategory `msgpack:"category,omitempty"`
	Message   string        `msgpack:"message,omitempty"`
	Timestamp int64         `msgpack:"timestamp"`
}

// SimulationError wraps an error with a well-defined ErrorCategory.
type SimulationError struct {
	Category ErrorCategory
	Err      error
}

func (e *SimulationError) Error() string {
	if e.Err == nil {
		return string(e.Category)
	}
	return e.Err.Error()
}

func (e *SimulationError) Unwrap() error {
	return e.Err
}

func NewSimulationError(category ErrorCategory, err error) error {
	if err == nil {
		return nil
	}
	return &SimulationError{Category: category, Err: err}
}

func NewSimulationErrorf(category ErrorCategory, format string, args ...any) error {
	return &SimulationError{Category: category, Err: fmt.Errorf(format, args...)}
}

func CategorizeError(err error, fallback ErrorCategory) (ErrorCategory, string) {
	if err == nil {
		return ErrCategoryNone, ""
	}
	var simErr *SimulationError
	if errors.As(err, &simErr) && simErr.Category != ErrCategoryNone {
		return simErr.Category, simErr.Error()
	}
	return fallback, err.Error()
}
