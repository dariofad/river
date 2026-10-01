#!/usr/bin/env python3

import argparse
import sys
import time

import numpy as np
from active_manifest import active_cycles
from river_api import RiverSession, ebpf_format, get_time_array

CYCLES = active_cycles()


def generate_trajectory(model: str, config: str) -> dict:
    t = get_time_array(CYCLES)

    if model == "2" and config == "1":
        return {
            "x": ebpf_format(10 + 0.0001 * (t + 1), "float64"),
            "y": ebpf_format(np.full(CYCLES, 20), "float64"),
        }

    elif model == "3" and config == "3":
        return {
            "PedalAngle": ebpf_format(np.zeros(CYCLES), "float64"),
            "EngineSpeed": ebpf_format(np.zeros(CYCLES), "float64"),
        }

    elif model == "1" and config == "3":
        return {"d_rel": ebpf_format(np.zeros(451), "float64")}

    print(f"Warning: No predefined trajectory for m{model}_c{config}. Sending empty.")
    return {}


def generate_perturbation(model: str, config: str) -> list | None:
    """Returns a list of state perturbation dictionaries."""
    if model == "2" and config == "1":
        return [
            {
                "TIME": 5,
                "VALUE_SIZE": 8,
                "ADDR": 0x20018,  # replace according to your binary
                "TYPE": "float64",
                "VALUE": 50.0,
            }
        ]

    elif model == "3" and config == "3":
        return [
            {
                "TIME": 50,
                "VALUE_SIZE": 8,
                "ADDR": 0x30278,  # replace according to your binary
                "TYPE": "float64",
                "VALUE": 16.0,
            }
        ]

    elif model == "1" and config == "3":
        perturbations = []
        for i in range(30):
            perturbations.append(
                {
                    "TIME": 300 + i,
                    "VALUE_SIZE": 8,
                    "ADDR": 0x55555556E350,
                    "VALUE": 25.0,
                }
            )
        # return perturbations
        return []

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
    perturbations = generate_perturbation(args.model, args.config)

    try:
        with RiverSession(args.host, 8082) as session:
            print(f"[*] Connecting to {args.host}:8082...", file=sys.stderr)

            # 1. Send initial trajectory
            session.send_payload(trajectory)

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
