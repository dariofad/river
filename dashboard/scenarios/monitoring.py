from typing import Any

from .common import ScenarioRun, receive_ack, send_payload

LABEL = "Monitoring"
PORT = 8080
RESULTS = "redis"


def build_request(filename: str, manifest: dict[str, Any]) -> dict[str, Any]:
    cycles = manifest["settings"]["cycles"]
    time = range(cycles)
    if filename == "dualACC":
        return {"d_rel": [value / 1000.0 for value in time]}
    if filename == "Simulink2Code":
        return {}
    if filename == "fuel_control":
        return {"PedalAngle": [value / 100000.0 for value in time]}
    return {"y": [10.0] * cycles, "z": [100.0] * cycles}


def run(sock, trajectory: dict[str, Any], run: ScenarioRun) -> None:
    send_payload(sock, trajectory)
    run.state = ("complete", receive_ack(sock))
