from typing import Any

from .common import ScenarioRun, receive_ack, send_payload

LABEL = "Monitoring"
PORT = 8080
RESULTS = "redis"


def build_request(filename: str, manifest: dict[str, Any]) -> dict[str, Any]:
    cycles = manifest["settings"]["cycles"]
    time = range(cycles)
    if filename == "dualACC":
        return {"egoCar.egoCar_Y.d_rel": [value / 1000.0 for value in time]}
    if filename == "Simulink2Code":
        return {}
    if filename == "fuel_control":
        return {
            "AbstractFuelControl_M1.AbstractFuelControl_M1_U.PedalAngle": [
                value / 100000.0 for value in time
            ]
        }
    return {"Tester.extU.y": [10.0] * cycles, "Tester.extU.z": [100.0] * cycles}


def run(sock, trajectory: dict[str, Any], run: ScenarioRun, manifest_text: str) -> None:
    send_payload(sock, {"manifest": manifest_text, "trajectory": trajectory})
    run.state = ("complete", receive_ack(sock))
