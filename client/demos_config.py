import numpy as np

def M1_C1_trajectory() -> dict:

    drel = np.array([float(i)/1000 for i in range(801)], dtype=np.float64)
    trajectory = dict()
    trajectory["DREL"] = drel.tolist()

    return trajectory

def M2_C3_trajectory() -> dict:

    trajectory = dict()

    return trajectory

