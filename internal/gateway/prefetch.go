//go:build amd64

package gateway

// prefetch asks the cache for the line at the start of b, without waiting
// for it: a PREFETCHT0 on amd64 (assembly), a plain load elsewhere. The
// frames arrive by DMA and are cold; on these EPYCs inbound DMA bypasses the
// cache, and the first touch of a frame was a quarter of the receive core.
//
//go:noescape
func prefetch(b []byte)
