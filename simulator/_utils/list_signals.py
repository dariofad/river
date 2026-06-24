#!/usr/bin/env python3

import json
import sys
from collections import OrderedDict

config = json.load(sys.stdin)
TABLE = OrderedDict()
NOF_SIGNALS_READ, NOF_SIGNALS_WRITTEN = 0, 0
READS = config["READS"]
WRITES = config["WRITES"]


def summarize_signals(groups: dict[str, str]) -> None:
    for group in groups:
        offset = len(TABLE.keys())
        for pos, sign in enumerate(group["SIGNALS"]):  # type: ignore
            TABLE[offset + pos] = sign["NAME"]  # type: ignore


if READS:
    summarize_signals(READS)
    NOF_SIGNALS_READ = len(TABLE.keys())
if WRITES:
    summarize_signals(WRITES)
    NOF_SIGNALS_WRITTEN = len(TABLE.keys()) - NOF_SIGNALS_READ

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
