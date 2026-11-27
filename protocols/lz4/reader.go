package lz4

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/pierrec/lz4/v4"
)

const (
	frameMagic     = 0x184D2204
	skippableMagic = 0x184D2A50 // The low four bits of a skippable frame's magic are free.
	windowSize     = 64 << 10   // How far back a block may refer into the blocks before it.
)

var errCorrupt = errors.New("lz4: corrupt frame")

// reader decodes LZ4 frames a block at a time, returning what a block held as soon as it arrives.
// lz4.Reader instead waits for the blocks that fill the caller's buffer, which stalls a conn whose peer awaits a reply before it sends more.
// It verifies no checksums, leaving integrity to the carrier.
type reader struct {
	src *bufio.Reader
	err error

	inFrame         bool
	linked          bool // Blocks refer into the window of those before them.
	blockChecksum   bool
	contentChecksum bool
	blockMax        int

	raw     []byte // The block as read from src.
	block   []byte // The decoded block.
	pending []byte // The part of the decoded block not yet read.
	window  []byte // The last windowSize decoded bytes of a frame of linked blocks.
}

func newReader(r io.Reader) *reader {
	return &reader{src: bufio.NewReader(r)}
}

func (r *reader) Read(b []byte) (int, error) {
	for len(r.pending) == 0 {
		if r.err != nil {
			return 0, r.err
		}
		if len(b) == 0 {
			return 0, nil
		}
		r.err = r.next()
	}
	n := copy(b, r.pending)
	r.pending = r.pending[n:]
	return n, nil
}

// next reads up to the end of the next block, leaving what it held in pending.
func (r *reader) next() error {
	if !r.inFrame {
		return r.header()
	}
	size, err := r.uint32()
	if err != nil {
		return err
	}
	if size == 0 {
		r.inFrame = false
		if r.contentChecksum {
			_, err = r.src.Discard(4)
		}
		return noEOF(err)
	}
	stored := size&(1<<31) != 0
	n := int(size &^ (1 << 31))
	if n > r.blockMax {
		return fmt.Errorf("%w: block of %d bytes over the frame's %d", errCorrupt, n, r.blockMax)
	}
	if cap(r.block) < r.blockMax {
		r.block = make([]byte, r.blockMax)
	}
	dst := r.block[:r.blockMax]
	if stored {
		dst = dst[:n]
		_, err = io.ReadFull(r.src, dst)
	} else {
		if cap(r.raw) < n {
			r.raw = make([]byte, n)
		}
		if _, err = io.ReadFull(r.src, r.raw[:n]); err == nil {
			n, err = lz4.UncompressBlockWithDict(r.raw[:n], dst, r.window)
			if err != nil {
				return fmt.Errorf("%w: %w", errCorrupt, err)
			}
			dst = dst[:n]
		}
	}
	if err == nil && r.blockChecksum {
		_, err = r.src.Discard(4)
	}
	if err != nil {
		return noEOF(err)
	}
	if r.linked {
		if len(dst) >= windowSize {
			r.window = append(r.window[:0], dst[len(dst)-windowSize:]...)
		} else {
			if over := len(r.window) + len(dst) - windowSize; over > 0 {
				r.window = r.window[:copy(r.window, r.window[over:])]
			}
			r.window = append(r.window, dst...)
		}
	}
	r.pending = dst
	return nil
}

// header reads a frame's descriptor, or skips a skippable frame.
func (r *reader) header() error {
	magic, err := r.uint32()
	if err != nil {
		return err
	}
	if magic&^0xF == skippableMagic {
		size, err := r.uint32()
		if err == nil {
			_, err = io.CopyN(io.Discard, r.src, int64(size))
		}
		return noEOF(err)
	}
	if magic != frameMagic {
		return fmt.Errorf("%w: magic %#x", errCorrupt, magic)
	}
	var d [2]byte
	if _, err := io.ReadFull(r.src, d[:]); err != nil {
		return noEOF(err)
	}
	flg, bd := d[0], d[1]
	if flg>>6 != 1 {
		return fmt.Errorf("%w: version %d", errCorrupt, flg>>6)
	}
	if id := bd >> 4 & 7; id < 4 {
		return fmt.Errorf("%w: block size id %d", errCorrupt, id)
	} else {
		r.blockMax = 1 << (8 + 2*int(id))
	}
	r.linked = flg&(1<<5) == 0
	r.blockChecksum = flg&(1<<4) != 0
	r.contentChecksum = flg&(1<<2) != 0
	rest := 1 // The header checksum.
	if flg&(1<<3) != 0 {
		rest += 8 // The content size.
	}
	if flg&1 != 0 {
		rest += 4 // The dictionary id.
	}
	if _, err := r.src.Discard(rest); err != nil {
		return noEOF(err)
	}
	r.window = r.window[:0]
	r.inFrame = true
	return nil
}

// uint32 reads a little-endian word, keeping io.EOF for a source ending before its first byte.
func (r *reader) uint32() (uint32, error) {
	var b [4]byte
	if _, err := io.ReadFull(r.src, b[:]); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(b[:]), nil
}

func noEOF(err error) error {
	if err == io.EOF {
		return io.ErrUnexpectedEOF
	}
	return err
}
