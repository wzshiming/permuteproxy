// Package pool shares the copy buffers of the proxy servers.
package pool

import (
	"sync"
)

// DefaultSize is the length of every buffer Bytes hands out.
const DefaultSize = 32 * 1024

// bytesPool keeps its buffers as array pointers, which enter a sync.Pool without the allocation a slice header costs.
type bytesPool struct {
	pool sync.Pool
}

// Get returns a buffer of DefaultSize bytes.
func (b *bytesPool) Get() []byte {
	return b.pool.Get().(*[DefaultSize]byte)[:]
}

// Put takes back a buffer of at least DefaultSize bytes of capacity and drops any other.
func (b *bytesPool) Put(d []byte) {
	if cap(d) < DefaultSize {
		return
	}
	b.pool.Put((*[DefaultSize]byte)(d[:DefaultSize]))
}

// Bytes is the pool the servers share.
var Bytes = &bytesPool{
	pool: sync.Pool{
		New: func() any {
			return new([DefaultSize]byte)
		},
	},
}
