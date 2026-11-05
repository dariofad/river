#!/usr/bin/env python3

import argparse
import sys
import time

import numpy as np
from active_manifest import active_cycles, read_active_manifest_text
from river_api import RiverSession, ebpf_format, get_time_array

CYCLES = active_cycles()


def generate_trajectory(model: str, config: str) -> dict:
    t = get_time_array(CYCLES)

    if model == "2" and config == "1":
        return {
            "Simulink2Code.Simulink2Code_U.x": ebpf_format(
                10 + 0.0001 * (t + 1), "float64"
            ),
            "Simulink2Code.Simulink2Code_U.y": ebpf_format(
                np.full(CYCLES, 20), "float64"
            ),
        }

    elif model == "3" and config == "3":
        return {
            "AbstractFuelControl_M1.AbstractFuelControl_M1_U.PedalAngle": ebpf_format(
                np.zeros(CYCLES), "float64"
            ),
            "AbstractFuelControl_M1.AbstractFuelControl_M1_U.EngineSpeed": ebpf_format(
                np.zeros(CYCLES), "float64"
            ),
        }

    elif model == "1" and config == "3":
        return {"egoCar.egoCar_Y.d_rel": ebpf_format(np.zeros(451), "float64")}

    print(f"Warning: No predefined trajectory for m{model}_c{config}. Sending empty.")
    return {}


def generate_perturbation(model: str, config: str) -> list | None:
    """Returns a list of state perturbation dictionaries."""
    if model == "2" and config == "1":
        return [
            {
                "TIME": 5,
                "NAME": "Simulink2Code.model_offset",
                "VALUE": 50.0,
            }
        ]

    elif model == "3" and config == "3":
        return [
            {
                "TIME": 50,
                "NAME": (
                    "AbstractFuelControl_M1."
                    "AbstractFuelControl_M1_P.Baseopeningangle_Value"
                ),
                "VALUE": 16.0,
            }
        ]

    elif model == "1" and config == "3":
        perturbations = []
        for i in range(30):
            perturbations.append(
                {
                    "TIME": 300 + i,
                    "NAME": "egoCar.egoCar_X.Integrator1_CSTATE",
                    "VALUE": 25.0,
                }
            )
        return perturbations

    return None


def main():
    parser = argparse.ArgumentParser(description="Run a state perturbation experiment.")
    parser.add_argument("host", help="Server hostname or IP address")
    parser.add_argument("model", help="Model id")
    parser.add_argument("config", help="Config id")
    args = parser.parse_args()

    print(f"host:\t{args.host}\nmodel:\t{args.model}\nconfig:\t{args.config}")
    print(f"cycles:\t{CYCLES}")

    trajectory = generate_trajectory(args.model, args.config)
    manifest_text = read_active_manifest_text()
    perturbations = generate_perturbation(args.model, args.config)

    try:
        with RiverSession(args.host, 8082) as session:
            print(f"[*] Connecting to {args.host}:8082...", file=sys.stderr)

            # 1. Send initial trajectory
            session.send_payload({"manifest": manifest_text, "trajectory": trajectory})

            # 2. Wait for simulation started ACK
            ack = session.wait_for_ack(64)
            print(ack)

            # 3. Send state perturbation
            if perturbations is not None:
                if args.model == "2" and args.config == "1":
                    time.sleep(3)

                session.send_payload(perturbations)

                # wait for perturbation ack
                p_ack = session.wait_for_ack(64)
                print(p_ack)

            # 4. Wait for end of simulation
            final_resp = session.wait_for_ack(64)
            print(final_resp)

    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()
