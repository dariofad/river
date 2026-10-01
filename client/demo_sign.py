#!/usr/bin/env python3

import argparse
import random
import sys
import time

import numpy as np
from active_manifest import active_cycles
from river_api import RiverSession, ebpf_format, get_time_array

CYCLES = active_cycles()


def generate_trajectory(model: str, config: str) -> dict:
    """
    You can use native numpy/pandas directly and format trajectory for eBPF.
    """
    t = get_time_array(CYCLES)

    if model == "1" and config == "2":
        return {"d_rel": ebpf_format(t / 1000.0, "float64")}

    elif model == "2" and config == "1":
        return {
            "x": ebpf_format(10 + 0.0001 * (t + 1), "float64"),
            "y": ebpf_format(np.full(CYCLES, 20), "float64"),
        }

    elif model == "3" and config == "2":
        return {
            "PedalAngle": ebpf_format(t / 100000.0, "float64"),
            "EngineSpeed": ebpf_format(t / 100000.0, "float64"),
        }

    elif model == "3" and config == "4":
        return {"PedalAngle": ebpf_format(np.zeros(CYCLES), "float64")}

    else:
        print(
            f"Warning: No predefined trajectory for m{model}_c{config}. Sending empty."
        )
        return {}


def generate_perturbation(
    model: str, config: str, period: int, iterno: int
) -> dict | None:
    """Generates a live perturbation dictionary."""
    if model == "1" and config == "2":
        return {
            "d_rel": ebpf_format([100.0], "float64"),
            "time": ebpf_format([798], "int32"),
        }

    elif model == "2" and config == "1":
        t_sub = get_time_array(period // 2)
        period_start = 0 if iterno == 0 else period + random.randint(0, period // 2)
        return {
            "x": ebpf_format(0.001 * (t_sub + 1), "float64"),
            "y": ebpf_format(np.full(period // 2, 0.02), "float64"),
            "time": ebpf_format(
                np.arange(period_start, period_start + period // 2), "int32"
            ),
        }

    return None


def main():
    parser = argparse.ArgumentParser(
        description="Run a signal perturbation experiment (refactored)."
    )
    parser.add_argument("host", help="Server hostname or IP address")
    parser.add_argument("model", help="Model id")
    parser.add_argument("config", help="Config id")
    args = parser.parse_args()

    # 1. Create Trajectory Locally (No network connection yet)
    print(
        f"[*] Generating trajectory for Model {args.model}, Config {args.config} "
        + f" (Cycles: {CYCLES})"
    )
    initial_trajectory = generate_trajectory(args.model, args.config)

    injections = 2 if int(args.model) == 2 else 1

    # 2. Setup Simulation (Network Phase)
    print(f"[*] Connecting to {args.host}:8083...")
    try:
        with RiverSession(args.host, 8083) as session:
            print("[+] Connected successfully!")

            # Send initial trajectory and WAIT for the start ACK
            session.send_payload(initial_trajectory)
            ack = session.wait_for_ack(64)
            print(f"[Server]: {ack}")

            # 3. Live Perturbations Loop
            for iterno in range(injections):
                period = CYCLES // 2
                perturbation = generate_perturbation(
                    args.model, args.config, period, iterno
                )

                if perturbation is None:
                    break

                print(f"[*] Sending perturbation {iterno + 1}/{injections}...")
                session.send_payload(perturbation)

                # WAIT for perturbation ACK
                p_ack = session.wait_for_ack(64)
                print(f"[Server]: {p_ack}")

                if iterno + 1 != injections:
                    time.sleep(random.randint(1, period // 2))

            # WAIT for final response
            final_resp = session.wait_for_ack(64)
            print(f"[Final]: {final_resp}")

    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()
