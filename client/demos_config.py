import numpy as np
import random

def monit_M1_C1_trajectory() -> dict:
    drel = np.array([float(i)/1000 for i in range(801)], dtype=np.float64)
    trajectory = dict()
    trajectory["DREL"] = drel.tolist()
    return trajectory

def monit_M2_C2_trajectory() -> dict:
    trajectory = dict()
    return trajectory

def monit_M3_C1_trajectory() -> dict:
    pangle = np.array([float(i)/100000 for i in range(1001)], dtype=np.float64)
    trajectory = dict()
    trajectory["PANGLE"] = pangle.tolist()
    return trajectory

def fals_M1_C1_trajectory() -> dict:
    drel = np.array([float(i)/1000 for i in range(801)], dtype=np.float64)
    trajectory = dict()
    trajectory["DREL"] = drel.tolist()
    return trajectory

def fals_M2_C1_trajectory() -> dict:
    x = np.array([float(i)*0.01 for i in range(20)], dtype=np.float64)
    y = np.array([float(i)*0.1 for i in range(20)], dtype=np.float64)    
    trajectory = dict()
    trajectory["X"] = x.tolist()
    trajectory["Y"] = y.tolist()    
    return trajectory

def fals_M3_C2_trajectory() -> dict:
    pangle = np.array([float(i)/100000 for i in range(1001)], dtype=np.float64)
    rpm = np.array([float(i)/100000 for i in range(1001)], dtype=np.float64)    
    trajectory = dict()
    trajectory["PANGLE"] = pangle.tolist()
    trajectory["RPM"] = rpm.tolist()    
    return trajectory

def sign_M1_C2_trajectory(CYCLES=0) -> dict:
    drel = np.array([float(i)/1000 for i in range(CYCLES)], dtype=np.float64)
    trajectory = dict()
    trajectory["DREL"] = drel.tolist()
    return trajectory

def sign_M1_C2_perturbation(PERIOD=0, ITERNO=0) -> dict:
    drel = np.array([100.0], dtype=np.float64)    
    PERIOD_START = 800
    time_trace = [PERIOD_START]
    perturbation = dict()
    perturbation["DREL"] = drel.tolist()
    perturbation["time"] = np.array(time_trace, dtype=np.int32).tolist()
    return perturbation

def sign_M2_C1_trajectory(CYCLES=0) -> dict:
    X = np.array([10 + 0.0001 * (i + 1) for i in range(CYCLES)], dtype=np.float64)
    Y = np.array([20 for _ in range(CYCLES)], dtype=np.float64)
    trajectory = dict()
    trajectory["X"] = X.tolist()
    trajectory["Y"] = Y.tolist()
    return trajectory

def sign_M2_C1_perturbation(PERIOD=0, ITERNO=0) -> dict:
    X = np.array([0.001 * (i + 1) for i in range(PERIOD)], dtype=np.float64)
    Y = np.array([0.02 for _ in range(PERIOD)], dtype=np.float64)
    PERIOD_START = 0 if ITERNO == 0 else PERIOD + random.randint(0, PERIOD // 2)
    time_trace = [PERIOD_START + i for i in range(PERIOD // 2)]
    perturbation = dict()
    perturbation["X"] = X.tolist()
    perturbation["Y"] = Y.tolist()
    perturbation["time"] = np.array(time_trace, dtype=np.int32).tolist()
    return perturbation

def sign_M3_C2_trajectory(CYCLES=0) -> dict:
    pangle = np.array([float(i)/100000 for i in range(CYCLES)], dtype=np.float64)
    rpm = np.array([float(i)/100000 for i in range(CYCLES)], dtype=np.float64)    
    trajectory = dict()
    trajectory["PANGLE"] = pangle.tolist()
    trajectory["RPM"] = rpm.tolist()    
    return trajectory

def sign_M3_C2_perturbation(PERIOD=0, ITERNO=0) -> dict:
    pangle = np.array([-float(i) for i in range(10)], dtype=np.float64)
    PERIOD_START = 990
    time_trace = [PERIOD_START + i for i in range(10)]
    perturbation = dict()
    perturbation["PANGLE"] = pangle.tolist()
    perturbation["time"] = np.array(time_trace, dtype=np.int32).tolist()
    return perturbation


def state_M2_C1_trajectory(CYCLES=0) -> dict:
    X = np.array([10 + 0.0001 * (i + 1) for i in range(CYCLES)], dtype=np.float64)
    Y = np.array([20 for _ in range(CYCLES)], dtype=np.float64)
    trajectory = dict()
    trajectory["X"] = X.tolist()
    trajectory["Y"] = Y.tolist()
    return trajectory

def state_M2_C1_perturbation(PERIOD=0, ITERNO=0) -> dict:
    TIME = np.uint32(5).item()
    VALUE_SIZE = np.uint32(8).item()
    ADDR = np.uint64(0x555555558040).item()
    VALUE = np.uint64(50).item()
    perturbation = dict()
    perturbation["TIME"] = TIME
    perturbation["VALUE_SIZE"] = VALUE_SIZE
    perturbation["ADDR"] = ADDR
    perturbation["VALUE"] = VALUE
    return perturbation
