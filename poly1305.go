// Package poly1305 provides a Go wrapper around floodyberry's optimized
// implementation of Poly1305.
// Poly1305 is a message authentication code (MAC) designed to meet the standard
// notion of unforgeability after a single message. After the sender
// authenticates one message, an attacker cannot find authenticators for any
// other messages.
// The sender MUST NOT use Poly1305 to authenticate more than one message under
// the same key. Authenticators for two messages under the same key should be
// expected to reveal enough information to allow forgeries of authenticators
// on other messages.
package poly1305

// BUG(codahale): Only supports AMD64.

// +build: amd64

import (
	// #cgo CFLAGS: -O3
	// #include "poly1305-donna.h"
	"C"
	"errors"
	"hash"
)

var (
	// ErrInvalidKey is returned when the provided key is not 256 bits long.
	ErrInvalidKey = errors.New("poly1305: invalid key length")
)

const (
	// KeySize is the length of Poly1305 keys, in bytes.
	KeySize = 32
	// BlockSize is the length of Poly1305 blocks, in bytes.
	BlockSize = 16
	// Size is the length of Poly1305 digests, in bytes.
	Size = 16
)

// A Poly1305 is an instance of Poly1305 using a particular key.
type Poly1305 struct {
	key   []byte
	state C.poly1305_state
}

// New creates and returns a keyed Hash implementation. The key argument must be
// 256 bits long, the value of which must only be used once.
func New(key []byte) (hash.Hash, error) {
	if len(key) != KeySize {
		return nil, ErrInvalidKey
	}

	h := new(Poly1305)
	h.key = make([]byte, KeySize)
	copy(h.key, key)
	h.Reset()

	return h, nil
}

// BlockSize returns the hash's underlying block size.
// The Write method must be able to accept any amount
// of data, but it may operate more efficiently if all writes
// are a multiple of the block size.
func (*Poly1305) BlockSize() int {
	return BlockSize
}

// Size returns the number of bytes Sum will return.
func (*Poly1305) Size() int {
	return Size
}

// Reset resets the Hash to its initial state.
func (s *Poly1305) Reset() {
	C.poly1305_init(&s.state, (*C.uchar)(&s.key[0]))
}

// Write (via the embedded io.Writer interface) adds more data to the running
// hash. It never returns an error.
func (s *Poly1305) Write(buf []byte) (int, error) {
	var p *C.uchar
	if len(buf) > 0 {
		p = (*C.uchar)(&buf[0])
	}

	C.poly1305_update(&s.state, p, (C.size_t)(len(buf)))

	return len(buf), nil
}

// Sum appends the current hash to b and returns the resulting slice.
// It does not change the underlying hash state.
func (s *Poly1305) Sum(buf []byte) []byte {
	if len(buf) < s.Size() {
		buf = make([]byte, s.Size())
	} else {
		buf = buf[0:s.Size()]
	}

	C.poly1305_finish(&s.state, (*C.uchar)(&buf[0]))

	return buf
}
