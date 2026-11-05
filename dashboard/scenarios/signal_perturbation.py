import random
import time
from typing import Any

from .common import ScenarioRun, receive_ack, send_payload

LABEL = "Signal perturbation"
PORT = 8083
RESULTS = "redis"


def build_request(filename: str, manifest: dict[str, Any]) -> dict[str, Any]:
    cycles = manifest["settings"]["cycles"]
    time_values = range(cycles)
    if filename == "dualACC":
        trajectory = {
            "egoCar.egoCar_Y.d_rel": [value / 1000.0 for value in time_values]
        }
        perturbations = [
            {
                "delay": 0,
                "data": {"egoCar.egoCar_Y.d_rel": [100.0], "time": [798]},
            }
        ]
    elif filename == "Simulink2Code":
        trajectory = {
            "Simulink2Code.Simulink2Code_U.x": [
                10 + 0.0001 * (value + 1) for value in time_values
            ],
            "Simulink2Code.Simulink2Code_U.y": [20.0] * cycles,
        }
        period = cycles // 2
        count = period // 2
        perturbations = []
        for iteration in range(2):
            start = 0 if iteration == 0 else period + random.randint(0, period // 2)
            perturbations.append(
                {
                    "delay": 0 if iteration == 0 else random.randint(1, period // 2),
                    "data": {
                        "Simulink2Code.Simulink2Code_U.x": [
                            0.001 * (value + 1) for value in range(count)
                        ],
                        "Simulink2Code.Simulink2Code_U.y": [0.02] * count,
                        "time": list(range(start, start + count)),
                    },
                }
            )
    else:
        values = [value / 100000.0 for value in time_values]
        trajectory = {
            "AbstractFuelControl_M1.AbstractFuelControl_M1_U.PedalAngle": values,
            "AbstractFuelControl_M1.AbstractFuelControl_M1_U.EngineSpeed": values,
        }
        perturbations = [
            {
                "delay": 0,
                "data": {
                    "AbstractFuelControl_M1.AbstractFuelControl_M1_U.PedalAngle": [
                        -float(i) for i in range(10)
                    ],
                    "time": list(range(990, 1000)),
                },
            }
        ]
    return {"trajectory": trajectory, "perturbations": perturbations}


def run(sock, request: dict[str, Any], run: ScenarioRun, manifest_text: str) -> None:
    send_payload(sock, {"manifest": manifest_text, "trajectory": request["trajectory"]})
    receive_ack(sock)
    for perturbation in request["perturbations"]:
        if perturbation["delay"]:
            time.sleep(perturbation["delay"])
        send_payload(sock, perturbation["data"])
        receive_ack(sock)
    run.state = ("complete", receive_ack(sock))
