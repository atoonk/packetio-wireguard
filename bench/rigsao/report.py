#!/usr/bin/env python3
"""Turn bench/results/blog/results.csv into the tables the write-up uses.

Every published number is the median of the repeats of one point, and the offered
load is printed next to the delivered one: a row where they do not reconcile is a
row about the harness, not about WireGuard.

    report.py [results.csv]
"""
import csv, statistics, sys
from collections import defaultdict

path = sys.argv[1] if len(sys.argv) > 1 else "bench/results/blog/results.csv"
rows = [r for r in csv.DictReader(open(path)) if r["gate"] == "pass"]

def num(r, k):
    try:
        return float(r[k])
    except (TypeError, ValueError):
        return 0.0

KEY = ("mode", "variant", "dir", "queues", "frame", "threads", "spray")
groups = defaultdict(list)
for r in rows:
    groups[tuple(r[k] for k in KEY)].append(r)

def med(rs, k):
    return statistics.median(num(r, k) for r in rs)

def mpps(x):
    return f"{x/1e6:.2f}"

print(f"{len(rows)} gated measurements, {len(groups)} points\n")

print("== baselines (kernel and stock wireguard-go) ==")
print(f"{'mode':<11} {'frame':>5} {'thr':>4} {'n':>2} {'offered':>8} {'encrypted':>9} {'delivered':>9} {'loss%':>6} {'busy A':>6} {'busy B':>6}")
for k in sorted(groups, key=lambda k: (k[0], int(k[4]), int(k[5] or 0))):
    if k[0] not in ("kernel", "kernel-rps", "wggo"):
        continue
    rs = groups[k]
    print(f"{k[0]:<11} {k[4]:>5} {k[5] or '-':>4} {len(rs):>2} {mpps(med(rs,'offered_pps')):>8} "
          f"{mpps(med(rs,'encrypted_pps')):>9} {mpps(med(rs,'delivered_pps')):>9} "
          f"{med(rs,'loss_pct'):>6.1f} {med(rs,'busy_a'):>6.1f} {med(rs,'busy_b'):>6.1f}")

order = ["stock", "p1", "p2", "p3", "p4"]
label = {"stock": "unmodified wireguard-go", "p1": "0001 fast path",
         "p2": "0002 batch replay", "p3": "0003 wide window", "p4": "0004 timer throttle"}
print("\n== wgpio: delivered Mpps by queue count, 68-byte frames ==")
qs = sorted({int(k[3]) for k in groups if k[0] == "wgpio" and k[4] == "68" and k[2] == "fwd" and k[3]})
print(f"{'variant':<24} " + " ".join(f"{q:>6}" for q in qs))
for v in order:
    cells = []
    for q in qs:
        k = ("wgpio", v, "fwd", str(q), "68", "", "64")
        cells.append(mpps(med(groups[k], "delivered_pps")) if k in groups else "-")
    if any(c != "-" for c in cells):
        print(f"{label.get(v,v):<24} " + " ".join(f"{c:>6}" for c in cells))

print("\n== wgpio: every point ==")
print(f"{'variant':<7} {'dir':>4} {'q':>3} {'frame':>5} {'n':>2} {'offered':>8} {'encrypted':>9} {'delivered':>9} {'loss%':>6} {'busy A':>6} {'busy B':>6} {'missed B':>12}")
for k in sorted(groups, key=lambda k: (order.index(k[1]) if k[1] in order else 9, k[2], int(k[3] or 0), int(k[4]))):
    if k[0] != "wgpio":
        continue
    rs = groups[k]
    print(f"{k[1]:<7} {k[2]:>4} {k[3]:>3} {k[4]:>5} {len(rs):>2} {mpps(med(rs,'offered_pps')):>8} "
          f"{mpps(med(rs,'encrypted_pps')):>9} {mpps(med(rs,'delivered_pps')):>9} "
          f"{med(rs,'loss_pct'):>6.1f} {med(rs,'busy_a'):>6.1f} {med(rs,'busy_b'):>6.1f} {med(rs,'nic_missed_b'):>12.0f}")

failed = [r for r in csv.DictReader(open(path)) if r["gate"] != "pass"]
if failed:
    print(f"\n{len(failed)} points were aborted by the gate and are not in any table above.")
