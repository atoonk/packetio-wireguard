#!/usr/bin/env python3
"""Rebuild results.csv from the per-point logs.

Each log holds both boxes' raw counters before and after the window, so every
published number can be derived again rather than trusted. This exists because the
first version of the driver divided the counter delta by the length of the measurement
window, which is right for wgpio -- its generator runs for the whole window -- and
wrong for the kernel baselines, where traffic flows only while udpblast runs. That
understated every kernel and wireguard-go row by the ratio of the two, about 21%.

    bench/rigsao/recompute.py [logs dir] [out.csv]
"""
import csv, pathlib, re, sys

logs = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "bench/results/blog/logs")
out = pathlib.Path(sys.argv[2] if len(sys.argv) > 2 else "bench/results/blog/results.csv")

FIELDS = ["ts","mode","variant","dir","queues","cpus","tuncpu","spray","frame","threads",
          "repeat","offered_pps","encrypted_pps","delivered_pps","loss_pct","busy_a","busy_b",
          "nic_missed_b","fork_rev","gate","notes"]

def kv(line):
    d = {}
    for tok in line.split():
        if "=" in tok:
            k, v = tok.split("=", 1)
            try:
                d[k] = float(v)
            except ValueError:
                pass
    return d

rows = []
for f in sorted(logs.glob("*.log")):
    text = f.read_text()
    head = re.search(r"^=== (\S+)", text, re.M)
    meta = re.search(r"frame=(\d+) payload=(\d+) queues=(\S*) cpus=(\S*) tun-cpu=(\S*) secs=(\d+)", text)
    if not head or not meta or "gate ok" not in text:
        continue
    snaps = {m.group(1) + m.group(2): kv(m.group(3))
             for m in re.finditer(r"^([AB]) (before|after): +(.*)$", text, re.M)}
    if len(snaps) != 4:
        continue
    name = head.group(1)
    frame, _payload, queues, cpus, tuncpu, secs = meta.groups()
    secs = int(secs)
    mode = re.match(r"(kernel-rps|kernel|wggo-rps|wggo|wgpio)", name).group(1)
    variant = "-"
    if mode == "wgpio":
        variant = re.match(r"wgpio-(\w+?)-(fwd|rev)", name).group(1)
    dirn = "rev" if "-rev-" in name else "fwd"
    rep = re.search(r"-r(\d+)-\d+$", name)
    A0, A1, B0, B1 = snaps["Abefore"], snaps["Aafter"], snaps["Bbefore"], snaps["Bafter"]
    enc0, enc1, dec0, dec1 = (A0, A1, B0, B1) if dirn == "fwd" else (B0, B1, A0, A1)
    d = lambda a, b, k: b.get(k, 0) - a.get(k, 0)
    hz = A1.get("hz", 100) or 100
    wa, wb = d(A0, A1, "now") or 1.0, d(B0, B1, "now") or 1.0
    # wgpio generates for the whole window; udpblast runs for exactly secs of it.
    span = (d(enc0, enc1, "now") or 1.0) if mode == "wgpio" else float(secs)
    dspan = (d(dec0, dec1, "now") or 1.0) if mode == "wgpio" else float(secs)
    if mode == "wgpio":
        off = d(enc0, enc1, "gen") / span
        encd = (d(enc0, enc1, "fp_enc") + d(enc0, enc1, "tx_tunnel_slow")) / span
        dlv = d(dec0, dec1, "sink") / dspan
        missed = d(dec0, dec1, "nic_missed")
    else:
        encd = d(enc0, enc1, "wg0_tx") / span
        dlv = d(dec0, dec1, "wg0_rx") / dspan
        missed = d(dec0, dec1, "rx_out_of_buffer") + d(dec0, dec1, "rx_steer_missed_packets")
        m = re.search(r"udpblast.*?pps=(\d+)", text) or re.search(r"\bpps=(\d+)", text)
        off = float(m.group(1)) if m else encd
    rows.append({
        "ts": re.search(r"\((\S+)\)|$", text).group(1) or "",
        "mode": mode, "variant": variant, "dir": dirn,
        "queues": queues, "cpus": cpus, "tuncpu": tuncpu,
        "spray": "64" if mode == "wgpio" else "",
        "frame": frame, "threads": "" if mode == "wgpio" else "8",
        "repeat": rep.group(1) if rep else "1",
        "offered_pps": f"{off:.0f}", "encrypted_pps": f"{encd:.0f}", "delivered_pps": f"{dlv:.0f}",
        "loss_pct": f"{(1 - dlv/encd)*100 if encd > 0 else 0:.2f}",
        "busy_a": f"{d(A0,A1,'busy')/hz/wa:.2f}", "busy_b": f"{d(B0,B1,'busy')/hz/wb:.2f}",
        "nic_missed_b": f"{missed:.0f}", "fork_rev": "-", "gate": "pass",
        "notes": f"recomputed from {f.name}",
    })

with open(out, "w", newline="") as fh:
    w = csv.DictWriter(fh, fieldnames=FIELDS)
    w.writeheader()
    w.writerows(rows)
print(f"{len(rows)} points recomputed from {logs} into {out}")
