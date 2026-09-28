#!/usr/bin/env bash
# Build the five wgpio binaries of the benchmark ladder, each against one
# state of the wireguard-go fork, plus the stock wireguard-go command and the
# load generator.
#
#   bin/wgpio-stock  upstream ecfc5a8d5446, -tags stockwg: no fast path at all
#   bin/wgpio-p1     + patch 0001 (fast path), -tags wgreplay1: replay per packet
#   bin/wgpio-p2     + patch 0002 (ValidateCounters: one lock per batch)
#   bin/wgpio-p3     + patch 0003 (a 131008-counter replay window)
#   bin/wgpio-p4     + patch 0004 (the fast path touches the timers every 50 ms)
#
# One wgpio source tree builds all five: what changes between them is the
# fork checkout and the two build tags. bin/ladder.txt records which was
# which, so a number in the write-up can be traced to a binary and a commit.
#
#   bench/build-ladder.sh [output dir]
set -euo pipefail
cd "$(dirname "$0")/.."
REPO=$PWD
FORK=${FORK:-$REPO/../wireguard-go-packetio}
OUT=${1:-$REPO/bin}
UPSTREAM=ecfc5a8d5446
BRANCH=packetio

[ -d "$FORK/.git" ] || { echo "no fork at $FORK (set FORK=)"; exit 1; }
if [ -n "$(git -C "$FORK" status --porcelain)" ]; then
  echo "the fork at $FORK has uncommitted changes; the ladder must be built from committed states"; exit 1
fi
if [ -n "$(git status --porcelain)" ]; then
  echo "warning: $REPO has uncommitted changes; the ladder will record the HEAD commit, which is not what is being built" >&2
fi

echo "== the patch record must rebuild the fork =="
make check-patches

# The patch commits, oldest first: 0001..0004.
mapfile -t COMMITS < <(git -C "$FORK" log --reverse --format=%H "$UPSTREAM..$BRANCH")
[ "${#COMMITS[@]}" -eq 4 ] || { echo "expected 4 patch commits in $UPSTREAM..$BRANCH, found ${#COMMITS[@]}"; exit 1; }

was=$(git -C "$FORK" rev-parse --abbrev-ref HEAD)
[ "$was" = HEAD ] && was=$(git -C "$FORK" rev-parse HEAD)
restore() { git -C "$FORK" checkout -q "$was"; }
trap restore EXIT

mkdir -p "$OUT"
WGREV=$(git rev-parse --short HEAD)
: > "$OUT/ladder.txt"
build() { # <name> <fork commit> <tags>
  local name=$1 commit=$2 tags=$3
  git -C "$FORK" checkout -q "$commit"
  go build -trimpath -tags "$tags" -o "$OUT/$name" ./cmd/wgpio
  local subj
  subj=$(git -C "$FORK" log -1 --format='%h %s')
  printf '%-14s fork=%s  tags=%-16s wgpio=%s  sha256=%s\n' \
    "$name" "$subj" "$tags" "$WGREV" "$(sha256sum "$OUT/$name" | cut -c1-16)" >> "$OUT/ladder.txt"
  echo "built $name  ($subj)"
}

echo "== the ladder =="
build wgpio-stock "$UPSTREAM"     dpdk,stockwg
build wgpio-p1    "${COMMITS[0]}" dpdk,wgreplay1
build wgpio-p2    "${COMMITS[1]}" dpdk
build wgpio-p3    "${COMMITS[2]}" dpdk
build wgpio-p4    "${COMMITS[3]}" dpdk

# p2, p3 and p4 are the same source and the same tags: only the fork moved.
# If two of them ever come out byte-identical the ladder is measuring one
# binary three times, which is worth knowing before the rig time is spent.
for a in p2 p3 p4; do
  for b in p2 p3 p4; do
    [ "$a" \< "$b" ] || continue
    if cmp -s "$OUT/wgpio-$a" "$OUT/wgpio-$b"; then
      echo "wgpio-$a and wgpio-$b are byte-identical: the fork state did not change the binary"; exit 1
    fi
  done
done

echo "== stock wireguard-go and the load generator =="
git -C "$FORK" checkout -q "$UPSTREAM"
(cd "$FORK" && go build -trimpath -o "$OUT/wireguard-go" .)
printf '%-14s fork=%s  tags=%-16s wgpio=%s  sha256=%s\n' wireguard-go \
  "$(git -C "$FORK" log -1 --format='%h %s')" "-" "-" "$(sha256sum "$OUT/wireguard-go" | cut -c1-16)" >> "$OUT/ladder.txt"
go build -trimpath -o "$OUT/udpblast" ./bench/udpblast
printf '%-14s fork=%-52s tags=%-16s wgpio=%s  sha256=%s\n' udpblast "-" "-" "$WGREV" \
  "$(sha256sum "$OUT/udpblast" | cut -c1-16)" >> "$OUT/ladder.txt"

echo
cat "$OUT/ladder.txt"
