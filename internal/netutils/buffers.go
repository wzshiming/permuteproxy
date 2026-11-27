package netutils

import (
	"sync"
)

// BufferSize is the length of every buffer Buffers hands out.
const BufferSize = 32 * 1024

// bufferPool keeps its buffers as array pointers, which enter a sync.Pool without the allocation a slice header costs.
type bufferPool struct {
	pool sync.Pool
}

// Get returns a buffer of BufferSize bytes.
func (b *bufferPool) Get() []byte {
	return b.pool.Get().(*[BufferSize]byte)[:]
}

// Put takes back a buffer of at least BufferSize bytes of capacity and drops any other.
func (b *bufferPool) Put(d []byte) {
	if cap(d) < BufferSize {
		return
	}
	b.pool.Put((*[BufferSize]byte)(d[:BufferSize]))
}

// Buffers is the pool the servers share.
var Buffers = &bufferPool{
	pool: sync.Pool{
		New: func() any {
			return new([BufferSize]byte)
		},
	},
}
