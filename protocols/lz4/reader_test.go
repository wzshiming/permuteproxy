package lz4

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/pierrec/lz4/v4"
)

func TestReadReturnsABlockWithoutWaitingForMore(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	w := lz4.NewWriter(client)
	go func() {
		w.Write([]byte("hello"))
		w.Flush()
	}()
	server.SetDeadline(time.Now().Add(10 * time.Second))
	b := make([]byte, 1<<10)
	if n, err := newReader(server).Read(b); err != nil || string(b[:n]) != "hello" {
		t.Fatalf("Read = %q, %v; want the flushed block alone", b[:n], err)
	}
}

func TestReadFramesOfTheStandardWriter(t *testing.T) {
	// Half of the data compresses and half does not, so blocks come both compressed and stored.
	data := bytes.Repeat([]byte("permuteproxy "), 40<<10)
	for i := len(data) / 2; i < len(data); i++ {
		data[i] = byte(i * 2654435761 >> 13)
	}
	for name, opts := range map[string][]lz4.Option{
		"default":         nil,
		"block checksums": {lz4.BlockChecksumOption(true), lz4.BlockSizeOption(lz4.Block64Kb)},
		"no checksum":     {lz4.ChecksumOption(false), lz4.BlockSizeOption(lz4.Block256Kb)},
		"content size":    {lz4.SizeOption(uint64(len(data) / 2))},
	} {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			// Two frames back to back read as one stream.
			for _, half := range [][]byte{data[:len(data)/2], data[len(data)/2:]} {
				w := lz4.NewWriter(&buf)
				if err := w.Apply(opts...); err != nil {
					t.Fatal(err)
				}
				if _, err := w.Write(half); err != nil {
					t.Fatal(err)
				}
				if err := w.Close(); err != nil {
					t.Fatal(err)
				}
			}
			got, err := io.ReadAll(newReader(&buf))
			if err != nil || !bytes.Equal(got, data) {
				t.Fatalf("read %d bytes, %v; want the %d written", len(got), err, len(data))
			}
		})
	}
}

func TestReadLinkedBlocksAndSkippableFrames(t *testing.T) {
	stream := []byte{
		0x50, 0x2A, 0x4D, 0x18, 3, 0, 0, 0, 'x', 'y', 'z', // A skippable frame.
		0x04, 0x22, 0x4D, 0x18, 0x40, 0x40, 0xC0, // A frame of linked blocks of up to 64KB.
		8, 0, 0, 0x80, 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', // A stored block.
		9, 0, 0, 0, 0x04, 8, 0, 0x50, 'v', 'w', 'x', 'y', 'z', // A match of 8 bytes, 8 back into the block before, then 5 literals.
		0, 0, 0, 0, // The end mark.
	}
	got, err := io.ReadAll(newReader(bytes.NewReader(stream)))
	if err != nil || string(got) != "abcdefghabcdefghvwxyz" {
		t.Fatalf("read %q, %v", got, err)
	}
}

func TestReadRejectsCorruptFrames(t *testing.T) {
	for name, stream := range map[string][]byte{
		"magic":          {1, 2, 3, 4},
		"version":        {0x04, 0x22, 0x4D, 0x18, 0x00, 0x40, 0},
		"block size id":  {0x04, 0x22, 0x4D, 0x18, 0x60, 0x00, 0},
		"oversize block": {0x04, 0x22, 0x4D, 0x18, 0x60, 0x40, 0, 1, 0, 1, 0},
		"bad block":      {0x04, 0x22, 0x4D, 0x18, 0x60, 0x40, 0, 3, 0, 0, 0, 0xF0, 0xFF, 0xFF},
	} {
		if _, err := io.ReadAll(newReader(bytes.NewReader(stream))); !errors.Is(err, errCorrupt) {
			t.Errorf("%s: err = %v, want errCorrupt", name, err)
		}
	}
	// A stream cut inside a block is not a clean end.
	cut := []byte{0x04, 0x22, 0x4D, 0x18, 0x60, 0x40, 0, 8, 0, 0, 0x80, 'a'}
	if _, err := io.ReadAll(newReader(bytes.NewReader(cut))); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("cut block: err = %v, want io.ErrUnexpectedEOF", err)
	}
}
