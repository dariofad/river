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
        trajectory = {"d_rel": [value / 1000.0 for value in time_values]}
        perturbations = [
            {
                "delay": 0,
                "data": {"d_rel": [100.0], "time": [798]},
            }
        ]
    else:
        trajectory = {
            "x": [10 + 0.0001 * (value + 1) for value in time_values],
            "y": [20.0] * cycles,
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
                        "x": [0.001 * (value + 1) for value in range(count)],
                        "y": [0.02] * count,
                        "time": list(range(start, start + count)),
                    },
                }
            )
    return {"trajectory": trajectory, "perturbations": perturbations}


def run(sock, request: dict[str, Any], run: ScenarioRun) -> None:
    send_payload(sock, request["trajectory"])
    receive_ack(sock)
    for perturbation in request["perturbations"]:
        if perturbation["delay"]:
            time.sleep(perturbation["delay"])
        send_payload(sock, perturbation["data"])
        receive_ack(sock)
    run.state = ("complete", receive_ack(sock))
