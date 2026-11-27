package pool

import (
	"testing"
)

func TestGetReturnsAFullBuffer(t *testing.T) {
	buf := Bytes.Get()
	defer Bytes.Put(buf)
	if len(buf) != DefaultSize {
		t.Fatalf("Get returned %d bytes, want %d", len(buf), DefaultSize)
	}
}

func TestPutTakesAShortenedBuffer(t *testing.T) {
	buf := Bytes.Get()
	Bytes.Put(buf[:1])
	if got := Bytes.Get(); len(got) != DefaultSize {
		t.Fatalf("Get after Put of a shortened buffer returned %d bytes, want %d", len(got), DefaultSize)
	}
}

func TestPutDropsABufferTooSmall(t *testing.T) {
	Bytes.Put(nil)
	Bytes.Put(make([]byte, DefaultSize-1))
	if got := Bytes.Get(); len(got) != DefaultSize {
		t.Fatalf("Get after Put of a small buffer returned %d bytes, want %d", len(got), DefaultSize)
	}
}

func BenchmarkGetPut(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		Bytes.Put(Bytes.Get())
	}
}
