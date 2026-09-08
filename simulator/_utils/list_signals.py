#!/usr/bin/env python3

import sys
from collections import OrderedDict

import yaml

manifest = yaml.safe_load(sys.stdin)
TABLE = OrderedDict()
NOF_SIGNALS_READ, NOF_SIGNALS_WRITTEN = 0, 0


def summarize_signals(action: str) -> None:
    global NOF_SIGNALS_READ, NOF_SIGNALS_WRITTEN
    for model in manifest.get("models", []):
        if not model.get("enabled", False):
            continue
        names = {
            data["path"]: data["name"]
            for category in ("inputs", "outputs", "states")
            for data in model.get(category, [])
        }
        for hook in model.get("hooks", []):
            if hook.get("action") != action:
                continue
            for path in hook.get("data", []):
                TABLE[len(TABLE)] = names[path]
                if action == "read":
                    NOF_SIGNALS_READ += 1
                else:
                    NOF_SIGNALS_WRITTEN += 1


summarize_signals("read")
summarize_signals("write")

if not TABLE.keys():
    exit()
max_sign_name_len = max([len(n) for n in TABLE.values()]) + 1
if NOF_SIGNALS_READ > 0:
    print("READS")
for pos, skey in enumerate(TABLE.keys()):
    if pos == NOF_SIGNALS_READ:
        print("WRITES")
    name = TABLE[skey]
    rjust_rx = name.rjust(12)
    ljust_sx = (str(skey) + ":").ljust(max_sign_name_len)
    print(f"\t{ljust_sx}{rjust_rx}")
