#!/usr/bin/env python3

import argparse
import sys

import numpy as np
from river_api import RiverSession, ebpf_format, get_time_array


def generate_trajectory(model: str, config: str) -> dict:
    if model == "1" and config == "1":
        t = get_time_array(800, step=1.0)
        return {"d_rel": ebpf_format(t / 1000.0, "float64")}

    elif model == "2" and config == "2":
        return {}

    elif model == "3" and config == "1":
        t = get_time_array(1001, step=1.0)
        return {"PedalAngle": ebpf_format(t / 100000.0, "float64")}

    elif model == "4" and config == "1":
        t = get_time_array(10, step=1.0)
        return {
            "y": ebpf_format(np.full(10, 10.0), "float64"),
            "z": ebpf_format(np.full(10, 100.0), "float64"),
        }

    print(f"Warning: No predefined trajectory for M{model}_C{config}. Sending empty.")
    return {}


def main():
    parser = argparse.ArgumentParser(description="Run a monitoring experiment.")
    parser.add_argument("host", help="Server hostname or IP address")
    parser.add_argument("model", help="Model id")
    parser.add_argument("config", help="Config id")
    args = parser.parse_args()

    print(f"host:\t{args.host}\nmodel:\t{args.model}\nconfig:\t{args.config}")

    trajectory = generate_trajectory(args.model, args.config)

    try:
        with RiverSession(args.host, 8080) as session:
            print(f"[*] Connecting to {args.host}:8080...", file=sys.stderr)
            session.send_payload(trajectory)

            # Wait for response
            if session.sock:
                response = session.sock.recv(4096)
                print(response.decode("utf-8"))

    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()
