#!/usr/bin/env python3
import argparse
import json
from typing import Dict
import subprocess

maps = {
    "uprobe_read_i",
    "uprobe_read_o",
    "uprobe_timer",
    "uprobe_write_i"
}

def parse_configuration(configuration: str) -> Dict:
    config = dict()
    config["uprobe_timer"] = {"nof_signals": 1}
    try:
        with open(configuration, 'r') as file:
            c = json.load(file)
        config["mm_ratio"] = c["MINOR_TO_MAJOR_RATIO"]
        config["nof_cycles"] = c["NOF_CYCLES"]        
        nof_signals = 0
        if c["WRITE_TIMING_I"]:
            nof_signals = len(c["WRITE_TIMING_I"]["SIGNALS"])
        config["uprobe_write_i"] = {"nof_signals": nof_signals}
        nof_signals = 0
        if c["READ_TIMING_I"]:
            nof_signals = len(c["READ_TIMING_I"]["SIGNALS"])
        config["uprobe_read_i"] = {"nof_signals": nof_signals}
        nof_signals = 0
        if c["READ_TIMING_O"]:
            nof_signals = len(c["READ_TIMING_O"]["SIGNALS"])
        config["uprobe_read_o"] = {"nof_signals": nof_signals}        
    except FileNotFoundError:
        print(f"Error: The file '{configuration}' was not found.")
    except json.JSONDecodeError:
        print(f"Error: Could not decode JSON from the file.")
    return config

def parse_stats(filename: str, configuration: str) -> (Dict, Dict):
    config = parse_configuration(configuration)
    stats = dict()
    try:
        with open(filename, 'r') as file:
            data = json.load(file)
        for dmap in data:
            if not dmap.get("name", False) or dmap['name'] not in maps:
                continue
            probename = dmap["name"]
            if not dmap.get("run_time_ns", False):
                # uprobe not loaded
                continue
            run_time_ns = dmap["run_time_ns"]
            run_cnt = dmap["run_cnt"]
            stats[probename] = dict()
            stats[probename]["avg_runtime"] = run_time_ns / (run_cnt)            
            stats[probename]["avg_runtime_ps"] = run_time_ns / (run_cnt * config[probename]["nof_signals"])
    except FileNotFoundError:
        print(f"Error: The file '{filename}' was not found.")
    except json.JSONDecodeError:
        print(f"Error: Could not decode JSON from the file.")
    return (config, stats)

def extract_stats(config:dict, stats: dict):
    for up in sorted(maps):
        print("---")
        if not stats.get(up, False):
            print(f"{up} not loaded")
            continue
        print(f"{up}")
        match up:
            case "uprobe_timer":
                print(f"avg_runtime:\t\t{stats[up]["avg_runtime"]/1000:.3f} µs")
            case _:
                print(f"avg_runtime:\t\t{stats[up]["avg_runtime"]/1000:.3f} µs")
                estimate = stats[up]["avg_runtime"] * int(config["mm_ratio"])
                estimate -= 2 * stats["uprobe_timer"]["avg_runtime"]
                print(f"avg_runtime_est:\t{estimate/1000:.3f} µs")           
                print(f"avg_runtime_ps:\t\t{stats[up]["avg_runtime_ps"]/1000:.3f} µs")
                estimate_ps = estimate / config[up]["nof_signals"]
                print(f"avg_runtime_ps_est:\t{estimate_ps/1000:.3f} µs")                
                
def main():
    parser = argparse.ArgumentParser(description='Collects eBPF program data with bpftool and computes performance statistics')
    parser.add_argument('--filename', type=str, help='bpftool JSON report file')
    parser.add_argument('--configuration', type=str, help='configuration')    
    args = parser.parse_args()
    with open(args.filename + ".json", "w") as f:
        subprocess.run(["sudo", "bpftool", "prog", "list", "--json", "--pretty"], stdout=f, stderr=subprocess.STDOUT)
    config, stats = parse_stats(args.filename + ".json", args.configuration)
    extract_stats(config, stats)

if __name__ == "__main__":
    main()
