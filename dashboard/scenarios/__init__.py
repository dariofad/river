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

DEMO_MANIFESTS = {
    "dualACC": ["m1_c1.river.yaml", "m1_c2.river.yaml", "m1_c3.river.yaml"],
    "Simulink2Code": ["m2_c1.river.yaml", "m2_c2.river.yaml"],
    "fuel_control": ["m3_c1.river.yaml", "m3_c2.river.yaml", "m3_c3.river.yaml"],
    "Tester": ["m4_c1.river.yaml"],
}
