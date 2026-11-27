package netutils

import (
	"testing"
)

func TestGetReturnsAFullBuffer(t *testing.T) {
	buf := Buffers.Get()
	defer Buffers.Put(buf)
	if len(buf) != BufferSize {
		t.Fatalf("Get returned %d bytes, want %d", len(buf), BufferSize)
	}
}

func TestPutTakesAShortenedBuffer(t *testing.T) {
	buf := Buffers.Get()
	Buffers.Put(buf[:1])
	if got := Buffers.Get(); len(got) != BufferSize {
		t.Fatalf("Get after Put of a shortened buffer returned %d bytes, want %d", len(got), BufferSize)
	}
}

func TestPutDropsABufferTooSmall(t *testing.T) {
	Buffers.Put(nil)
	Buffers.Put(make([]byte, BufferSize-1))
	if got := Buffers.Get(); len(got) != BufferSize {
		t.Fatalf("Get after Put of a small buffer returned %d bytes, want %d", len(got), BufferSize)
	}
}

func BenchmarkGetPut(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		Buffers.Put(Buffers.Get())
	}
}
