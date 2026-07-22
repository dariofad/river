import random

import numpy as np

# Canonical data identifiers from the generated manifests.  These are the
# Code Descriptor implementation names accepted by River, not legacy demo
# abbreviations such as PANGLE, RPM, DREL, X, or Y.
EGO_D_LEAD = "d_lead"
TOY_X = "x"
TOY_Y = "y"
# Code Descriptor graphical names are accepted by the runtime as aliases for
# the generated implementation identifiers (PedalAngle and EngineSpeed).
AFC_PEDAL_ANGLE = "Pedal Angle"
AFC_ENGINE_SPEED = "Engine Speed"
AFC_INTEGRATOR_STATE = (
    "AbstractFuelControl_M1.AbstractFuelControl_M1_X.Integrator_CSTATE"
)


def monit_M1_C1_trajectory() -> dict:
    drel = np.array([float(i) / 1000 for i in range(800)], dtype=np.float64)
    trajectory = dict()
    trajectory[EGO_D_LEAD] = drel.tolist()
    return trajectory


def monit_M2_C2_trajectory() -> dict:
    trajectory = dict()
    return trajectory


def monit_M3_C1_trajectory() -> dict:
    pangle = np.array([float(i) / 100000 for i in range(1001)], dtype=np.float64)
    trajectory = dict()
    trajectory[AFC_PEDAL_ANGLE] = pangle.tolist()
    return trajectory


def fals_M1_C1_trajectory() -> dict:
    drel = np.array([float(i) / 1000 for i in range(800)], dtype=np.float64)
    trajectory = dict()
    trajectory[EGO_D_LEAD] = drel.tolist()
    return trajectory


def fals_M2_C1_trajectory() -> dict:
    x = np.array([float(i) * 0.01 for i in range(20)], dtype=np.float64)
    y = np.array([float(i) * 0.1 for i in range(20)], dtype=np.float64)
    trajectory = dict()
    trajectory[TOY_X] = x.tolist()
    trajectory[TOY_Y] = y.tolist()
    return trajectory


def fals_M3_C2_trajectory() -> dict:
    pangle = np.array([float(i) / 100000 for i in range(1001)], dtype=np.float64)
    rpm = np.array([float(i) / 100000 for i in range(1001)], dtype=np.float64)
    trajectory = dict()
    trajectory[AFC_PEDAL_ANGLE] = pangle.tolist()
    trajectory[AFC_ENGINE_SPEED] = rpm.tolist()
    return trajectory


def sign_M1_C2_trajectory(CYCLES: int = 0) -> dict:
    drel = np.array([float(i) / 1000 for i in range(CYCLES)], dtype=np.float64)
    trajectory = dict()
    trajectory[EGO_D_LEAD] = drel.tolist()
    return trajectory


def sign_M1_C2_perturbation(PERIOD: int = 0, ITERNO: int = 0) -> dict:
    drel = np.array([100.0], dtype=np.float64)
    PERIOD_START = 800
    time_trace = [PERIOD_START]
    perturbation = dict()
    perturbation[EGO_D_LEAD] = drel.tolist()
    perturbation["time"] = np.array(time_trace, dtype=np.int32).tolist()
    return perturbation


def sign_M2_C1_trajectory(CYCLES: int = 0) -> dict:
    X = np.array([10 + 0.0001 * (i + 1) for i in range(CYCLES)], dtype=np.float64)
    Y = np.array([20 for _ in range(CYCLES)], dtype=np.float64)
    trajectory = dict()
    trajectory[TOY_X] = X.tolist()
    trajectory[TOY_Y] = Y.tolist()
    return trajectory


def sign_M2_C1_perturbation(PERIOD: int = 0, ITERNO: int = 0) -> dict:
    # One replacement value is required for each requested logical cycle.
    # Keep these arrays aligned with ``time_trace`` below.
    update_length = PERIOD // 2
    X = np.array([0.001 * (i + 1) for i in range(update_length)], dtype=np.float64)
    Y = np.array([0.02 for _ in range(update_length)], dtype=np.float64)
    PERIOD_START = 0 if ITERNO == 0 else PERIOD + random.randint(0, PERIOD // 2)
    time_trace = [PERIOD_START + i for i in range(update_length)]
    perturbation = dict()
    perturbation[TOY_X] = X.tolist()
    perturbation[TOY_Y] = Y.tolist()
    perturbation["time"] = np.array(time_trace, dtype=np.int32).tolist()
    return perturbation


def sign_M3_C2_trajectory(CYCLES: int = 0) -> dict:
    pangle = np.array([float(i) / 100000 for i in range(CYCLES)], dtype=np.float64)
    rpm = np.array([float(i) / 100000 for i in range(CYCLES)], dtype=np.float64)
    trajectory = dict()
    trajectory[AFC_PEDAL_ANGLE] = pangle.tolist()
    trajectory[AFC_ENGINE_SPEED] = rpm.tolist()
    return trajectory


def sign_M3_C2_perturbation(PERIOD: int = 0, ITERNO: int = 0) -> dict:
    pangle = np.array([-float(i) for i in range(10)], dtype=np.float64)
    PERIOD_START = 990
    time_trace = [PERIOD_START + i for i in range(10)]
    perturbation = dict()
    perturbation[AFC_PEDAL_ANGLE] = pangle.tolist()
    perturbation["time"] = np.array(time_trace, dtype=np.int32).tolist()
    return perturbation


def state_M2_C1_trajectory(CYCLES: int = 0) -> dict:
    X = np.array([10 + 0.0001 * (i + 1) for i in range(CYCLES)], dtype=np.float64)
    Y = np.array([20 for _ in range(CYCLES)], dtype=np.float64)
    trajectory = dict()
    trajectory[TOY_X] = X.tolist()
    trajectory[TOY_Y] = Y.tolist()
    return trajectory


def state_M2_C1_perturbation(PERIOD: int = 0, ITERNO: int = 0) -> list:
    return []


def state_M3_C3_trajectory(CYCLES: int = 0) -> dict:
    pangle = np.array([0.0 for i in range(CYCLES)], dtype=np.float64)
    rpm = np.array([0.0 for i in range(CYCLES)], dtype=np.float64)
    trajectory = dict()
    trajectory[AFC_PEDAL_ANGLE] = pangle.tolist()
    trajectory[AFC_ENGINE_SPEED] = rpm.tolist()
    return trajectory


def state_M3_C3_perturbation(PERIOD: int = 0, ITERNO: int = 0) -> list | None:
    TIME = np.uint32(50).item()
    VALUE = np.float64(16).item()
    perturbation = dict()
    perturbation["TIME"] = TIME
    perturbation["STATE"] = AFC_INTEGRATOR_STATE
    perturbation["VALUE"] = VALUE
    #    return None
    return [perturbation]


def state_M1_C3_trajectory(CYCLES: int = 0) -> dict:
    drel = np.array([0 for i in range(451)], dtype=np.float64)
    trajectory = dict()
    trajectory[EGO_D_LEAD] = drel.tolist()
    return trajectory


def state_M1_C3_perturbation(PERIOD: int = 0, ITERNO: int = 0) -> list:
    return []


def sign_M3_C4_trajectory(CYCLES: int = 0) -> dict:
    pangle = np.array([0.0 for _ in range(CYCLES)], dtype=np.float64)
    trajectory = dict()
    trajectory[AFC_PEDAL_ANGLE] = pangle.tolist()
    return trajectory


def sign_M3_C4_perturbation(PERIOD: int = 0, ITERNO: int = 0) -> dict | None:
    angles = [float(i) / 30 for i in range(450)]
    pangle = np.array(angles, dtype=np.float64)
    PERIOD_START = 50
    time_trace = [PERIOD_START + i for i in range(450)]
    perturbation = dict()
    perturbation[AFC_PEDAL_ANGLE] = pangle.tolist()
    perturbation["time"] = np.array(time_trace, dtype=np.int32).tolist()
    return perturbation


# return None
