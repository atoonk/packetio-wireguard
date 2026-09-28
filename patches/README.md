# Patches to wireguard-go

wgpio runs a fork of upstream wireguard-go: `golang.zx2c4.com/wireguard` at
commit `ecfc5a8d5446` (2026-05-22) plus the patches in this directory, in
order. The fork is consumed through the `replace` directive in go.mod.

This directory is the auditable record of every change. It is generated from
the fork with `make patches` and checked with `make check-patches`, which
applies the patches to a clean upstream checkout and compares the tree to the
fork: a stale record would otherwise silently rebuild an older fork.

Each patch has an entry in [../docs/CHANGES-TO-WIREGUARD-GO.md](../docs/CHANGES-TO-WIREGUARD-GO.md)
with the reason, the security argument and the numbers that justified it.
