#!/usr/bin/env python3

import argparse
import sys

import msgpack
from river_api import RiverSession, ebpf_format, get_time_array


def generate_trajectory(model: str, config: str) -> dict:
    if model == "1" and config == "1":
        t = get_time_array(800)
        return {"d_rel": ebpf_format(t / 1000.0, "float64")}

    elif model == "2" and config == "1":
        t = get_time_array(20)
        return {
            "x": ebpf_format(t * 0.01, "float64"),
            "y": ebpf_format(t * 0.1, "float64"),
        }

    elif model == "3" and config == "2":
        t = get_time_array(1001)
        return {
            "PedalAngle": ebpf_format(t / 100000.0, "float64"),
            "EngineSpeed": ebpf_format(t / 100000.0, "float64"),
        }

    print(f"Warning: No predefined trajectory for m{model}_c{config}. Sending empty.")
    return {}


def main():
    parser = argparse.ArgumentParser(description="Run a falsification experiment.")
    parser.add_argument("host", help="Server hostname or IP address")
    parser.add_argument("model", help="Model id")
    parser.add_argument("config", help="Config id")
    args = parser.parse_args()

    print(f"host:\t{args.host}\nmodel:\t{args.model}\nconfig:\t{args.config}")

    trajectory = generate_trajectory(args.model, args.config)

    try:
        with RiverSession(args.host, 8081) as session:
            print(f"[*] Connecting to {args.host}:8081...", file=sys.stderr)
            session.send_payload(trajectory)

            # Wait for data (prefixed with 4-byte length)
            print("[*] Receiving response data...", file=sys.stderr)
            result_bytes = session.receive_data()

            if result_bytes:
                unpacked_res = msgpack.unpackb(result_bytes)
                print("(...first 15 output trace records)")
                for sign in unpacked_res.get("OUT_SIGNALS", []):
                    print(sign["NAME"])
                    print(*(sign["VALUES"][:15]), "...")
            else:
                print("No data received.")

    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()
