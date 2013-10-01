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

type poly1305 struct {
	key   []byte
	state C.poly1305_state
}

// New creates and returns a keyed Hash implementation. The key argument must be
// 256 bits long, the value of which must only be used once.
func New(key []byte) (hash.Hash, error) {
	if len(key) != KeySize {
		return nil, ErrInvalidKey
	}

	h := new(poly1305)
	h.key = make([]byte, KeySize)
	copy(h.key, key)
	h.Reset()

	return h, nil
}

func (*poly1305) BlockSize() int {
	return BlockSize
}

func (*poly1305) Size() int {
	return Size
}

func (s *poly1305) Reset() {
	C.poly1305_init(&s.state, (*C.uchar)(&s.key[0]))
}

func (s *poly1305) Write(buf []byte) (int, error) {
	var p *C.uchar
	if len(buf) > 0 {
		p = (*C.uchar)(&buf[0])
	}

	C.poly1305_update(&s.state, p, (C.size_t)(len(buf)))

	return len(buf), nil
}

func (s *poly1305) Sum(buf []byte) []byte {
	var mac [Size]byte
	C.poly1305_finish(&s.state, (*C.uchar)(&mac[0]))
	return append(buf, mac[0:]...)
}
