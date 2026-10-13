from typing import Any

import msgpack

from .common import ScenarioRun, receive_payload, send_payload

LABEL = "Falsification"
PORT = 8081
RESULTS = "response"


def build_request(filename: str, manifest: dict[str, Any]) -> dict[str, Any]:
    cycles = manifest["settings"]["cycles"]
    time = range(cycles)
    if filename == "dualACC":
        return {"d_rel": [value / 1000.0 for value in time]}
    if filename == "Simulink2Code":
        return {
            "x": [value * 0.01 for value in time],
            "y": [value * 0.1 for value in time],
        }
    values = [value / 100000.0 for value in time]
    return {"PedalAngle": values, "EngineSpeed": values}


def run(sock, trajectory: dict[str, Any], run: ScenarioRun) -> None:
    send_payload(sock, trajectory)
    run.result = msgpack.unpackb(receive_payload(sock), raw=False)
    run.state = ("complete", "Falsification completed.")
