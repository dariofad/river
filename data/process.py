#!/usr/bin/env python3
import argparse
import json
import subprocess

import yaml

PROGRAMS = {"uprobe_model_entry", "uprobe_model_return"}


def parse_manifest(path: str) -> dict[str, int]:
    with open(path, encoding="utf-8") as file:
        manifest = yaml.safe_load(file)
    selected_models = [model for model in manifest["models"] if model.get("selected")]
    entry_values = sum(
        sum(1 for value in model.get(category, []) if value.get("selected"))
        for model in selected_models
        for category in ("inputs", "states")
    )
    return_values = sum(
        sum(1 for value in model.get(category, []) if value.get("selected"))
        for model in selected_models
        for category in ("inputs", "outputs")
    )
    return {
        "uprobe_model_entry": entry_values,
        "uprobe_model_return": return_values,
    }


def parse_stats(filename: str, manifest: str) -> dict[str, dict[str, float]]:
    counts = parse_manifest(manifest)
    with open(filename, encoding="utf-8") as file:
        programs = json.load(file)
    stats = {}
    for program in programs:
        name = program.get("name")
        if name not in PROGRAMS or not program.get("run_time_ns"):
            continue
        runs = program["run_cnt"]
        average = program["run_time_ns"] / runs
        stats[name] = {
            "average": average,
            "average_per_value": average / max(1, counts[name]),
        }
    return stats


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Collect River eBPF runtime statistics"
    )
    parser.add_argument("--filename", required=True, help="output basename")
    parser.add_argument("--manifest", required=True, help="River YAML manifest")
    args = parser.parse_args()
    report = args.filename + ".json"
    with open(report, "w", encoding="utf-8") as file:
        subprocess.run(
            ["sudo", "bpftool", "prog", "list", "--json", "--pretty"],
            stdout=file,
            stderr=subprocess.STDOUT,
            check=True,
        )
    for name, values in sorted(parse_stats(report, args.manifest).items()):
        print(f"{name}: {values['average'] / 1000:.3f} µs")
        print(f"{name} per selected value: {values['average_per_value'] / 1000:.3f} µs")


if __name__ == "__main__":
    main()
