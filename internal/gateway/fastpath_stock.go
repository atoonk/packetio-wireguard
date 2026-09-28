//go:build stockwg

package gateway

// The fast path, compiled out. This build is linked against unmodified
// wireguard-go, which has none of the API fastpath.go needs -- keypair
// accessors, nonce reservation, the replay window as a batch, the keypair
// observer -- so the whole of it is replaced here by the little the rest of
// the gateway refers to. Every entry point is unreachable: Config.FastPath
// is refused by the command's validate(), so rxQueue.fpOn is never set.
//
// What remains is the stock path, which is wireguard-go's own pipeline over
// packetio's frames: the Bind hands received datagrams up, the TUN parks LAN
// frames (and the generator's, gen.go) for RoutineReadFromTUN. That is the
// measurement this build exists to make.

import (
	"github.com/atoonk/packetio"

	"github.com/atoonk/packetio-wireguard/internal/ether"
)

// fpTable is the receiver-index table the fast path keeps; there is nothing
// to keep here, but Gateway holds one, so it keeps its type.
type fpTable struct{}

func newFPTable() *fpTable { return &fpTable{} }

// fpBatch is one receive turn's fast-path work: none.
type fpBatch struct{}

// fpVerdict is what the fast path did with a frame. It is always fpPunt in
// this build: the stock path takes everything.
type fpVerdict int

const (
	fpPunt fpVerdict = iota
	fpForwarded
	fpDropped
)

func (g *Gateway) fpDecrypt(rq *rxQueue, d packetio.Desc, f []byte, l ether.Link, h ether.IPv4, u ether.UDP, payload []byte) fpVerdict {
	return fpPunt
}

func (g *Gateway) fpEncrypt(rq *rxQueue, d packetio.Desc, f []byte, l ether.Link, h ether.IPv4) fpVerdict {
	return fpPunt
}

func (g *Gateway) fpReclaim(rq *rxQueue) {}
func (g *Gateway) fpFlush(rq *rxQueue)   {}
