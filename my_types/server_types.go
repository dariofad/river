package my_types

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
