#!/usr/bin/env python3
"""Summarise bench/results/rig3/results.csv.

For every (mode, bin, queues, frame) it prints the ladder as medians over repeats, and
names the "clean" rate: the highest offered rate whose median loss is under 1%, which
is the number the write-up quotes. Peak delivered is shown too, because past the knee
some modes keep delivering more at higher loss and some collapse, and that shape is
worth a sentence.

    bench/rig3/report.py [results.csv]
"""
import csv
import statistics
import sys
from collections import defaultdict

path = sys.argv[1] if len(sys.argv) > 1 else __file__.rsplit('/bench/', 1)[0] + '/bench/results/rig3/results.csv'
rows = [r for r in csv.DictReader(open(path)) if r['repeat'] != '0']  # 0 = the up gate's warmup

groups = defaultdict(lambda: defaultdict(list))
for r in rows:
    # The note is part of the configuration: the flags a wgpio mode was started
    # with ride in it as "[...]", and an experiment's rows carry its tag (the
    # grid's rows carry none), so a tuning that changed between runs never gets
    # averaged with what it replaced.
    key = (r['mode'], r['bin'], int(r['queues']), int(r['frame']), r['note'].strip('"'))
    groups[key][int(r['pps_req'])].append(r)

def med(rs, k):
    return statistics.median(float(r[k]) for r in rs)

def fmt(v):
    return f"{v/1e6:7.2f} M" if v >= 1e6 else f"{v/1e3:7.0f} k"

summary = []
for key in sorted(groups, key=lambda k: (k[3], k[0], k[1], k[2])):
    mode, binn, q, frame, extra = key
    label = f"{mode}{' ' + binn if binn != 'none' else ''} q{q} {frame} B {extra}".rstrip()
    print(f"\n== {label}")
    print(f"{'offered':>10} {'delivered':>10} {'loss%':>6} {'busy A':>7} {'busy B':>7}  limiter (n)")
    clean, peak = None, (0, None)
    for pps in sorted(groups[key]):
        rs = groups[key][pps]
        off, dlv, loss = med(rs, 'offered'), med(rs, 'delivered'), med(rs, 'loss_pct')
        lim = max(set(r['limiter'] for r in rs), key=[r['limiter'] for r in rs].count)
        print(f"{fmt(off):>10} {fmt(dlv):>10} {loss:6.2f} {med(rs, 'busy_a'):7.1f} {med(rs, 'busy_b'):7.1f}  {lim} ({len(rs)})")
        if loss < 1.0:
            clean = (off, dlv)
        if dlv > peak[0]:
            peak = (dlv, off)
    summary.append((label, clean, peak))

print("\n\n== clean rate (median loss < 1%) and peak delivered, per configuration")
print(f"{'configuration':<64} {'clean':>10} {'peak':>10}  (peak at offered)")
for label, clean, peak in summary:
    c = fmt(clean[1]) if clean else '     none'
    print(f"{label:<64} {c:>10} {fmt(peak[0]):>10}  ({fmt(peak[1])})")
