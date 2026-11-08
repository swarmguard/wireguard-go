/* SPDX-License-Identifier: MIT */

package device

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"

	reference "golang.org/x/crypto/chacha20poly1305"
)

// TestDataAEADCompatibility checks transport interoperability with legacy peers,
// including in-place encryption and decryption with WireGuard header space.
func TestDataAEADCompatibility(t *testing.T) {
	t.Parallel()
	key := make([]byte, reference.KeySize)
	for i := range key {
		key[i] = byte(i)
	}
	selected, err := newDataAEAD(key)
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := reference.New(key)
	if err != nil {
		t.Fatal(err)
	}
	if selected.NonceSize() != legacy.NonceSize() || selected.Overhead() != legacy.Overhead() {
		t.Fatal("transport framing changed")
	}
	for _, size := range []int{0, 1, 16, 64, 1280, 2016, MaxMessageSize - MessageTransportSize} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			var nonce [reference.NonceSize]byte
			binary.LittleEndian.PutUint64(nonce[4:], uint64(size))
			plain := bytes.Repeat([]byte{byte(size)}, size)
			const prefix = MessageTransportHeaderSize
			buf := make([]byte, prefix+size, prefix+size+selected.Overhead())
			for i := 0; i < prefix; i++ {
				buf[i] = 0xa5
			}
			copy(buf[prefix:], plain)
			sealed := selected.Seal(buf[:prefix], nonce[:], buf[prefix:], nil)
			want := legacy.Seal(nil, nonce[:], plain, nil)
			if !bytes.Equal(sealed[prefix:], want) {
				t.Fatal("transport ciphertext differs from legacy cipher")
			}
			opened, err := legacy.Open(nil, nonce[:], sealed[prefix:], nil)
			if err != nil || !bytes.Equal(opened, plain) {
				t.Fatal("legacy peer cannot decrypt transport packet", err)
			}
			opened, err = selected.Open(sealed[:prefix], nonce[:], sealed[prefix:], nil)
			if err != nil || !bytes.Equal(opened[prefix:], plain) {
				t.Fatal("cannot decrypt legacy transport packet in place", err)
			}
			if !bytes.Equal(opened[:prefix], bytes.Repeat([]byte{0xa5}, prefix)) {
				t.Fatal("transport header overwritten")
			}
		})
	}
}

// TestDataAEADKeySize rejects invalid keys on every selected implementation.
func TestDataAEADKeySize(t *testing.T) {
	t.Parallel()
	for _, size := range []int{0, 1, 31, 33, 64} {
		if _, err := newDataAEAD(make([]byte, size)); err == nil {
			t.Fatalf("accepted key size %d", size)
		}
	}
}
