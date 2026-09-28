FORK ?= ../wireguard-go-packetio
UPSTREAM_COMMIT = ecfc5a8d5446
FORK_BRANCH = packetio

.PHONY: build ladder test patches check-patches
build:
	go build -tags dpdk -o bin/wgpio ./cmd/wgpio
# The five binaries of the benchmark ladder, one per state of the fork.
ladder:
	bench/build-ladder.sh
test:
	go test ./...
	go test -tags stockwg ./...
	sudo -E test/veth.sh
	sudo -E test/veth-gen.sh
# Regenerate the patch record from the fork.
patches:
	rm -f patches/*.patch
	git -C $(FORK) format-patch -q -o $(CURDIR)/patches $(UPSTREAM_COMMIT)..$(FORK_BRANCH)
# The record must rebuild the fork exactly.
check-patches:
	@tmp=$$(mktemp -d); git clone -q $(FORK) $$tmp/wg && git -C $$tmp/wg checkout -q $(UPSTREAM_COMMIT) && \
	  git -C $$tmp/wg am -q $(CURDIR)/patches/*.patch && \
	  a=$$(git -C $$tmp/wg write-tree) && b=$$(git -C $(FORK) rev-parse $(FORK_BRANCH)^{tree}) && \
	  rm -rf $$tmp && [ "$$a" = "$$b" ] && echo "patches match the fork ($$a)" || { echo "PATCH RECORD DOES NOT MATCH THE FORK"; exit 1; }
