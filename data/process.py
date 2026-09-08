#!/usr/bin/env python3
import argparse
import json
import subprocess

import yaml

maps = {"uprobe_read_i", "uprobe_read_o", "uprobe_timer", "uprobe_write_i"}


def parse_manifest(manifest_path: str) -> dict:
    config = dict()
    config["uprobe_timer"] = {"nof_signals": 1}
    try:
        with open(manifest_path) as file:
            manifest = yaml.safe_load(file)
        config["mm_ratio"] = manifest["settings"]["sample_every"]
        config["nof_cycles"] = manifest["settings"]["cycles"]
        reads = writes = 0
        for model in manifest["models"]:
            if not model.get("enabled", False):
                continue
            for hook in model.get("hooks", []):
                if hook["action"] == "read":
                    reads += len(hook["data"])
                elif hook["action"] == "write":
                    writes += len(hook["data"])
        config["uprobe_write_i"] = {"nof_signals": writes}
        config["uprobe_read_i"] = {"nof_signals": reads}
        config["uprobe_read_o"] = {"nof_signals": 0}
    except FileNotFoundError:
        print(f"Error: The file '{manifest_path}' was not found.")
    except yaml.YAMLError:
        print("Error: Could not decode YAML manifest.")
    return config


def parse_stats(filename: str, manifest_path: str) -> tuple[dict, dict]:
    config = parse_manifest(manifest_path)
    stats = dict()
    try:
        with open(filename) as file:
            data = json.load(file)
        for dmap in data:
            if not dmap.get("name", False) or dmap["name"] not in maps:
                continue
            probename = dmap["name"]
            if not dmap.get("run_time_ns", False):
                # uprobe not loaded
                continue
            run_time_ns = dmap["run_time_ns"]
            run_cnt = dmap["run_cnt"]
            stats[probename] = dict()
            stats[probename]["avg_runtime"] = run_time_ns / (run_cnt)
            stats[probename]["avg_runtime_ps"] = run_time_ns / (
                run_cnt * config[probename]["nof_signals"]
            )
    except FileNotFoundError:
        print(f"Error: The file '{filename}' was not found.")
    except json.JSONDecodeError:
        print("Error: Could not decode JSON from the file.")
    return (config, stats)


def extract_stats(config: dict, stats: dict) -> None:
    for up in sorted(maps):
        print("---")
        if not stats.get(up, False):
            print(f"{up} not loaded")
            continue
        print(f"{up}")
        match up:
            case "uprobe_timer":
                print(f"avg_runtime:\t\t{stats[up]['avg_runtime'] / 1000:.3f} µs")
            case _:
                print(f"avg_runtime:\t\t{stats[up]['avg_runtime'] / 1000:.3f} µs")
                estimate = stats[up]["avg_runtime"] * int(config["mm_ratio"])
                estimate -= 2 * stats["uprobe_timer"]["avg_runtime"]
                print(f"avg_runtime_est:\t{estimate / 1000:.3f} µs")
                print(f"avg_runtime_ps:\t\t{stats[up]['avg_runtime_ps'] / 1000:.3f} µs")
                estimate_ps = estimate / config[up]["nof_signals"]
                print(f"avg_runtime_ps_est:\t{estimate_ps / 1000:.3f} µs")


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Collects eBPF program data with bpftool and computes performance "
            "statistics"
        )
    )
    parser.add_argument("--filename", type=str, help="bpftool JSON report file")
    parser.add_argument("--manifest", type=str, help="River manifest")
    args = parser.parse_args()
    with open(args.filename + ".json", "w") as f:
        subprocess.run(
            ["sudo", "bpftool", "prog", "list", "--json", "--pretty"],
            stdout=f,
            stderr=subprocess.STDOUT,
        )
    config, stats = parse_stats(args.filename + ".json", args.manifest)
    extract_stats(config, stats)


if __name__ == "__main__":
    main()
