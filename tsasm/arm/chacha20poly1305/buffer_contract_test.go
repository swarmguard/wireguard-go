//go:build arm

/* SPDX-License-Identifier: MIT */

package chacha20poly1305

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/rand"
	"testing"

	reference "golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/sys/cpu"
)

// TestPacketLengthsAndScalarFallback checks all small-buffer lengths and legacy frames,
// including exact in-place buffers, prefixes, mixed peers and scalar fallback.
func TestPacketLengthsAndScalarFallback(t *testing.T) {
	original := cpu.ARM.HasNEON
	defer func() { cpu.ARM.HasNEON = original }()
	for _, neon := range []bool{original, false} {
		cpu.ARM.HasNEON = neon
		t.Run(fmt.Sprintf("neon=%v", neon), func(t *testing.T) {
			r := rand.New(rand.NewSource(42))
			key := make([]byte, 32)
			r.Read(key)
			nonce := make([]byte, 12)
			r.Read(nonce)
			a, _ := New(key)
			ref, _ := reference.New(key)
			sizes := make([]int, 2049)
			for n := range sizes {
				sizes[n] = n
			}
			sizes = append(sizes, 4096, 16384, 65519)
			for _, n := range sizes {
				plain := make([]byte, n)
				r.Read(plain)
				aad := make([]byte, n%33)
				r.Read(aad)
				expected := ref.Seal(nil, nonce, plain, aad)
				for _, prefix := range []int{0, 16} {
					buf := make([]byte, prefix+n, prefix+n+16)
					for k := 0; k < prefix; k++ {
						buf[k] = 0xa5
					}
					copy(buf[prefix:], plain)
					got := a.Seal(buf[:prefix], nonce, buf[prefix:], aad)
					if !bytes.Equal(got[prefix:], expected) {
						t.Fatalf("seal mismatch n=%d prefix=%d", n, prefix)
					}
					decoded, err := ref.Open(nil, nonce, got[prefix:], aad)
					if err != nil || !bytes.Equal(decoded, plain) {
						t.Fatal("legacy peer decrypt failed", n, err)
					}
					got, err = a.Open(got[:prefix], nonce, got[prefix:], aad)
					if err != nil || !bytes.Equal(got[prefix:], plain) {
						t.Fatal("in-place open failed", n, err)
					}
					for k := 0; k < prefix; k++ {
						if got[k] != 0xa5 {
							t.Fatal("prefix overwritten")
						}
					}
				}
			}
		})
	}
}

// TestBufferContract retains x/crypto misuse and authentication checks.
func TestBufferContract(t *testing.T) {
	mustPanic := func(t *testing.T, name string, f func()) {
		t.Helper()
		defer func() {
			if recover() == nil {
				t.Error(name + " did not panic")
			}
		}()
		f()
	}
	for _, c := range aeadCtors {
		t.Run(c.name, func(t *testing.T) {
			if _, err := c.new(make([]byte, 31)); err == nil {
				t.Fatal("invalid key accepted")
			}
			a, _ := c.new(make([]byte, 32))
			nonce := make([]byte, 12)
			plain := make([]byte, 64)
			mustPanic(t, "Seal nonce", func() { a.Seal(nil, nil, plain, nil) })
			mustPanic(t, "Open nonce", func() { a.Open(nil, nil, plain, nil) })
			for n := 0; n < 16; n++ {
				if _, err := a.Open(nil, nonce, make([]byte, n), nil); err == nil {
					t.Fatal("short ciphertext accepted")
				}
			}
			buf := make([]byte, 256)
			copy(buf, a.Seal(nil, nonce, plain, nil))
			mustPanic(t, "Seal input overlap", func() { a.Seal(buf[1:1], nonce, buf[:64], nil) })
			mustPanic(t, "Open input overlap", func() { a.Open(buf[1:1], nonce, buf[:80], nil) })
			ciphertext := a.Seal(nil, nonce, plain, nil)
			ciphertext[0] ^= 1
			dst := bytes.Repeat([]byte{0xa5}, 64)
			out, err := a.Open(dst[:0], nonce, ciphertext, nil)
			if err == nil || out != nil || !bytes.Equal(dst, make([]byte, 64)) {
				t.Fatal("authentication failure output contract")
			}
		})
	}
}

// TestAADOverlap rejects output overlapping additional authenticated data.
// Older x/crypto versions do not enforce this check, so test this implementation
// directly rather than requiring identical misuse behavior from the reference.
func TestAADOverlap(t *testing.T) {
	a, err := New(make([]byte, KeySize))
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, NonceSize)
	for _, open := range []bool{false, true} {
		t.Run(fmt.Sprintf("open=%v", open), func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("AAD overlap accepted")
				}
			}()
			plain := make([]byte, 64)
			buf := make([]byte, 256)
			copy(buf, a.Seal(nil, nonce, plain, nil))
			if open {
				a.Open(buf[:0], nonce, buf[:80], buf[:4])
			} else {
				a.Seal(buf[:0], nonce, plain, buf[:4])
			}
		})
	}
}

// TestCPUFeatures reports which implementation the actual ARM host selects.
func TestCPUFeatures(t *testing.T) { t.Logf("GOARCH=arm HasNEON=%v", cpu.ARM.HasNEON) }

// BenchmarkPacketAEAD compares preallocated transport-sized AEAD work.
func BenchmarkPacketAEAD(b *testing.B) {
	for _, n := range []int{64, 1280, 2016} {
		for _, c := range aeadCtors {
			for _, open := range []bool{true, false} {
				op := "Seal"
				if open {
					op = "Open"
				}
				b.Run(fmt.Sprintf("%d/%s/%s", n, c.name, op), func(b *testing.B) {
					a, _ := c.new(make([]byte, 32))
					nonce := make([]byte, 12)
					plain := make([]byte, n)
					ct := a.Seal(nil, nonce, plain, nil)
					out := make([]byte, 0, n+16)
					b.SetBytes(int64(n))
					b.ReportAllocs()
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						if open {
							if _, err := a.Open(out[:0], nonce, ct, nil); err != nil {
								b.Fatal(err)
							}
						} else {
							binary.LittleEndian.PutUint64(nonce[4:], uint64(i))
							a.Seal(out[:0], nonce, plain, nil)
						}
					}
				})
			}
		}
	}
}
