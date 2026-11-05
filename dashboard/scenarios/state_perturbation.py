import time
from typing import Any

from .common import ScenarioRun, receive_ack, send_payload

LABEL = "State perturbation"
PORT = 8082
RESULTS = "redis"


def build_request(filename: str, manifest: dict[str, Any]) -> dict[str, Any]:
    cycles = manifest["settings"]["cycles"]
    time_values = range(cycles)
    if filename == "dualACC":
        trajectory = {"egoCar.egoCar_Y.d_rel": [0.0] * cycles}
        perturbations = [
            {
                "TIME": 300 + i,
                "NAME": "egoCar.egoCar_X.Integrator1_CSTATE",
                "VALUE": 25.0,
            }
            for i in range(30)
        ]
        delay = 0
    elif filename == "Simulink2Code":
        trajectory = {
            "Simulink2Code.Simulink2Code_U.x": [
                10 + 0.0001 * (value + 1) for value in time_values
            ],
            "Simulink2Code.Simulink2Code_U.y": [20.0] * cycles,
        }
        perturbations = [
            {
                "TIME": 5,
                "NAME": "Simulink2Code.model_offset",
                "VALUE": 50.0,
            }
        ]
        delay = 3
    else:
        trajectory = {
            "AbstractFuelControl_M1.AbstractFuelControl_M1_U.PedalAngle": [0.0]
            * cycles,
            "AbstractFuelControl_M1.AbstractFuelControl_M1_U.EngineSpeed": [0.0]
            * cycles,
        }
        perturbations = [
            {
                "TIME": 50,
                "NAME": (
                    "AbstractFuelControl_M1."
                    "AbstractFuelControl_M1_P.Baseopeningangle_Value"
                ),
                "VALUE": 16.0,
            }
        ]
        delay = 0
    return {
        "trajectory": trajectory,
        "perturbations": perturbations,
        "delay": delay,
    }


def run(sock, request: dict[str, Any], run: ScenarioRun, manifest_text: str) -> None:
    send_payload(sock, {"manifest": manifest_text, "trajectory": request["trajectory"]})
    receive_ack(sock)
    if request["delay"]:
        time.sleep(request["delay"])
    send_payload(sock, request["perturbations"])
    receive_ack(sock)
    run.state = ("complete", receive_ack(sock))
