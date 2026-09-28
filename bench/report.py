#!/usr/bin/env python3
"""Turn run.sh CSVs into the benchmark table.

    bench/report.py bench/results/*.csv

For every (mode, size, dir) it reports the NDR (highest offered rate with loss <= 0.5%),
what the peers cost at that rate, and the peak delivered rate at any offered load.
"""
import csv, sys, collections

rows = []
for path in sys.argv[1:]:
    with open(path) as f:
        for r in csv.DictReader(f):
            try:
                r["tx"] = float(r["tx_kpps"]); r["rx"] = float(r["rx_kpps"]); r["loss"] = float(r["loss_pct"])
            except ValueError:
                continue
            rows.append(r)

groups = collections.OrderedDict()
for r in rows:
    groups.setdefault((r["mode"], int(r["size"]), r["dir"]), []).append(r)

def gbps(kpps, size):  # L1 line rate incl. 20 B preamble+IFG and 4 B FCS the size already counts
    return kpps * 1e3 * (size + 20) * 8 / 1e9

import re
def spinning(mode):
    """Cores wgpio dedicates to polling (receive queues + the TUN reader): busy by design,
    not by demand. wgpio-qN pins N receive goroutines and one reader."""
    m = re.match(r"wgpio(?:-fp)?-q(\d+)", mode)
    return int(m.group(1)) + 1 if m else 0

print("| mode | frame | dir | NDR kpps (loss) | peak rx kpps | Gbit/s @NDR | ash-2 cores | ash-3 cores | of which spinning | ash-3 hottest core |")
print("|---|---|---|---|---|---|---|---|---|---|")
for (mode, size, d), rs in groups.items():
    clean = [r for r in rs if r["loss"] <= 0.5 and r["rx"] > 0]
    ndr = max(clean, key=lambda r: r["rx"]) if clean else None
    peak = max(rs, key=lambda r: r["rx"])
    if ndr:
        sp = spinning(mode)
        print(f"| {mode} | {size} | {d} | {ndr['rx']:.0f} ({ndr['loss']:.2f}%) | {peak['rx']:.0f} | {gbps(ndr['rx'], size):.2f} | "
              f"{ndr['ash2_busy_cores']} | {ndr['ash3_busy_cores']} | {sp if sp else '-'} | {ndr.get('ash3_max_core_pct','')}% |")
    else:
        print(f"| {mode} | {size} | {d} | none clean | {peak['rx']:.0f} | | | | | |")
