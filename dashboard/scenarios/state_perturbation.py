import time
from typing import Any

from .common import ScenarioRun, receive_ack, send_payload

LABEL = "State perturbation"
PORT = 8082
RESULTS = "redis"


def build_request(filename: str, manifest: dict[str, Any]) -> dict[str, Any]:
    cycles = manifest["settings"]["cycles"]
    time_values = range(cycles)
    if filename == "Simulink2Code":
        trajectory = {
            "x": [10 + 0.0001 * (value + 1) for value in time_values],
            "y": [20.0] * cycles,
        }
        perturbations = [
            {
                "TIME": 5,
                "VALUE_SIZE": 8,
                "ADDR": 0x20018,
                "TYPE": "float64",
                "VALUE": 50.0,
            }
        ]
        delay = 3
    else:
        trajectory = {
            "PedalAngle": [0.0] * cycles,
            "EngineSpeed": [0.0] * cycles,
        }
        perturbations = [
            {
                "TIME": 50,
                "VALUE_SIZE": 8,
                "ADDR": 0x30278,
                "TYPE": "float64",
                "VALUE": 16.0,
            }
        ]
        delay = 0
    return {
        "trajectory": trajectory,
        "perturbations": perturbations,
        "delay": delay,
    }


def run(sock, request: dict[str, Any], run: ScenarioRun) -> None:
    send_payload(sock, request["trajectory"])
    receive_ack(sock)
    if request["delay"]:
        time.sleep(request["delay"])
    send_payload(sock, request["perturbations"])
    receive_ack(sock)
    run.state = ("complete", receive_ack(sock))
