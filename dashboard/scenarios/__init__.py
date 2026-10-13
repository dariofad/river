from . import falsification, monitoring, signal_perturbation, state_perturbation

SCENARIOS = {
    "monitoring": monitoring,
    "falsification": falsification,
    "state_perturbation": state_perturbation,
    "signal_perturbation": signal_perturbation,
}

SUPPORTED_BINARIES = {
    "monitoring": {"dualACC", "Simulink2Code", "fuel_control", "Tester"},
    "falsification": {"dualACC", "Simulink2Code", "fuel_control"},
    "state_perturbation": {"Simulink2Code", "fuel_control"},
    "signal_perturbation": {"dualACC", "Simulink2Code"},
}
