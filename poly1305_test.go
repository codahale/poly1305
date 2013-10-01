package poly1305

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"io"
	"testing"
)

// stolen from http://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-00#section-7
var testVectors = [][]string{
	[]string{
		"0000000000000000000000000000000000000000000000000000000000000000",
		"746869732069732033322d62797465206b657920666f7220506f6c7931333035",
		"49ec78090e481ec6c26b33b91ccc0307",
	},
	[]string{
		"48656c6c6f20776f726c6421",
		"746869732069732033322d62797465206b657920666f7220506f6c7931333035",
		"a6f745008f81c916a20dcc74eef2b2f0",
	},
}

func TestPoly1305(t *testing.T) {
	for i, vector := range testVectors {
		t.Logf("Running test vector %d", i)

		input, err := hex.DecodeString(vector[0])
		if err != nil {
			t.Error(err)
		}

		key, err := hex.DecodeString(vector[1])
		if err != nil {
			t.Error(err)
		}

		expected, err := hex.DecodeString(vector[2])
		if err != nil {
			t.Error(err)
		}

		h, err := New(key)
		if err != nil {
			t.Error(err)
		}

		h.Write(input)

		actual := h.Sum(nil)

		if !bytes.Equal(expected, actual) {
			t.Errorf("Bad MAC: expected %x, was %x", expected, actual)

			for i, v := range expected {
				if actual[i] != v {
					t.Logf("Mismatch at offset %d: %x vs %x", i, v, actual[i])
					break
				}
			}
		}
	}
}

func ExampleNew() {
	// A message for which we'd like to ensure authenticity.
	message := []byte("A message which must be authentic.")

	// NEVER USE THE SAME KEY TWICE. A critical aspect of Poly1305's design is
	// that if you use the same key twice for two messages, an attacker can
	// recover the key and forge messages. Poly1305 is generally assumed to be
	// used in combination with an encryption algorithm (e.g., ChaCha20), which
	// also requires a nonce. The Poly1305 key can be derived from the
	// encryption algorithm's key stream, in this case, as long as the algorithm
	// is used in a construction which requires a unique nonce or IV
	// (e.g., ChaCha20).
	key := make([]byte, KeySize)
	_, err := io.ReadFull(rand.Reader, key)
	if err != nil {
		panic(err)
	}

	// The sender calculates the MAC for the message it sends.
	sender, err := New(key)
	if err != nil {
		panic(err)
	}
	sender.Write(message)
	sent := sender.Sum(nil)

	// The receiver calculates the MAC for the message it received.
	receiver, err := New(key)
	if err != nil {
		panic(err)
	}
	receiver.Write(message)
	received := receiver.Sum(nil)

	// The receiver compares the two MACs (using a constant-time comparison
	// algorithm to prevent timing attacks), and iff they match is assured of
	// the message's authenticity.
	if subtle.ConstantTimeCompare(sent, received) != 1 {
		panic("Invalid message! Don't decrypt, process, or look at it.")
	}
}

const benchSize = 1024 * 1024

func BenchmarkPoly1305(b *testing.B) {
	b.SetBytes(benchSize)
	key := make([]byte, KeySize)
	input := make([]byte, benchSize)
	digest := make([]byte, 16)
	c, _ := New(key)
	for i := 0; i < b.N; i++ {
		c.Write(input)
	}
	c.Sum(digest)
}
