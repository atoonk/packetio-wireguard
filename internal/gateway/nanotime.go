package gateway

import _ "unsafe"

// nanotime is the runtime's monotonic clock without a time.Time allocation.
//
//go:linkname nanotime runtime.nanotime
func nanotime() int64
