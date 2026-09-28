# The R&D runs, 2026-09-19

Everything here was measured while the harness was still being debugged. The published
numbers are in `../blog/`, taken from a clean boot with the reviewed patch series.

Keep this directory. Three of its files are the only record that the published numbers
were corrected for real mistakes, and the profiles cannot be regenerated without a rig.

| file | what it is |
|---|---|
| `results.csv` | the last R&D state, 255 rows. Correct as far as it goes, but superseded |
| `logs/` | per-point logs holding both boxes' raw counters; `recompute.py` can re-derive any row from these |
| `logs/superseded/` | logs from before the sink and thread-count fixes |
| `profiles/` | pprof captures with a README whose two tables exist nowhere else |
| `results-bouncing-sink.csv` | **the evidence for mistake 1.** The sink routed the far prefix to `lo`, which does not discard: the decrypting box sent a packet back through the tunnel for roughly three of every four it received, so it paid an encrypt and a transmit on top of every decrypt. Cost the kernel baseline a factor of 2.7 |
| `results-wgpio-clock-error.csv` | **the evidence for mistake 2.** wgpio's counters come from a stats line it prints on its own schedule, and the rate was computed by dividing the delta by the wall-clock window. With a 5-second interval in a 24-second window that understates by up to 21%, and it showed up as an apparent bimodality: the same point delivering either 37 or 46 Mpps |
| `dry-run.csv`, `dry-run-dpdk-diagnosis.log` | harness smoke tests. The log is where the `dpdk-testpmd -i` exits-on-EOF bug was found, which had produced a confident "DPDK cannot receive on this hardware" verdict that was entirely wrong |

The third mistake left no file: the baselines were measured at full flood rather than a
rate ladder, which finds collapse instead of capacity. wireguard-go carried 231 kpps
when offered 2.2 Mpps and 1.2 kpps when offered 4.9 Mpps, against a true capacity near
290 k.
