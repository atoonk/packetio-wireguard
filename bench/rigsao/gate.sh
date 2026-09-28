#!/usr/bin/env bash
# The gate: proof that the tunnel actually carries traffic, run before every
# measurement point. A point whose gate fails is aborted, not published -- the first
# pass had rows in it that were really "nothing was running", and a benchmark that
# reports a zero as a number is worse than one that reports nothing.
#
#   gate.sh kernel|wggo        both directions of ping through wg0, then a 1420-byte
#                              packet with DF set, which proves the MTU end to end
#   gate.sh wgpio              a recent handshake on both boxes, then plaintext
#                              generated at the encrypting peer counted by the far
#                              sink; with no kernel netdev on the VLAN there is
#                              nothing to ping from, and this is the stronger check
set -euo pipefail
. "$(dirname "$0")/env.sh"
mode=$1
enc=${ENC:-$SAO2} dec=${DEC:-$SAO3}

case $mode in
kernel|wggo)
  encl=$([ "$enc" = "$SAO2" ] && echo $A_LAN || echo $B_LAN)
  decl=$([ "$dec" = "$SAO2" ] && echo $A_LAN || echo $B_LAN)
  for i in $(seq 30); do
    $SSH $USER@$enc "ping -c 1 -W 1 $decl" >/dev/null 2>&1 && break
    sleep 1
  done
  $SSH $USER@$enc "ping -c 2 -W 2 $decl" >/dev/null 2>&1 || { echo "GATE FAIL: $(name_of $enc) cannot ping $decl through the tunnel"; exit 1; }
  $SSH $USER@$dec "ping -c 2 -W 2 $encl" >/dev/null 2>&1 || { echo "GATE FAIL: $(name_of $dec) cannot ping $encl through the tunnel"; exit 1; }
  $SSH $USER@$enc "ping -c 2 -W 2 -M do -s 1392 $decl" >/dev/null 2>&1 || { echo "GATE FAIL: a full-MTU packet does not cross"; exit 1; }
  echo "gate ok: ping both ways and a 1420-byte packet cross the tunnel"
  ;;
wgpio)
  for i in $(seq 40); do
    ok=1
    for h in $enc $dec; do
      $SSH $USER@$h 'sudo wg show wgpio0 latest-handshakes 2>/dev/null | awk "{exit !(\$2>0)}"' || ok=0
    done
    [ "$ok" = 1 ] && break
    sleep 1
  done
  [ "${ok:-0}" = 1 ] || { echo "GATE FAIL: no handshake between $(name_of $enc) and $(name_of $dec)"; exit 1; }
  # The generator is already running; the sink must be counting it.
  s0=$($SSH $USER@$dec "sudo journalctl -u wgpio --no-pager -o cat | grep msg=stats | tail -1 | tr ' ' '\n' | grep '^sink=' | cut -d= -f2")
  sleep 6
  s1=$($SSH $USER@$dec "sudo journalctl -u wgpio --no-pager -o cat | grep msg=stats | tail -1 | tr ' ' '\n' | grep '^sink=' | cut -d= -f2")
  [ $(( ${s1:-0} - ${s0:-0} )) -gt 1000 ] || { echo "GATE FAIL: $(name_of $dec)'s sink counted $(( ${s1:-0} - ${s0:-0} )) packets; nothing is crossing"; exit 1; }
  echo "gate ok: handshake on both, $(name_of $dec) decrypting $(( s1 - s0 )) packets in 6 s"
  ;;
*) echo "gate.sh kernel|wggo|wgpio"; exit 2;;
esac
