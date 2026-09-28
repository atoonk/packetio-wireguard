//go:build !amd64

package gateway

func prefetch(b []byte) {
	if len(b) > 0 {
		sink = b[0]
	}
}

var sink byte
