//go:build arm64

// SPDX-License-Identifier: MIT
package chacha20poly1305

import (
	"bytes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"math/rand"
	"sync"
	"testing"

	ref "golang.org/x/crypto/chacha20poly1305"
)

// TestDifferential checks block boundaries, random inputs, corruption and reuse.
func TestDifferential(t *testing.T) {
	r := rand.New(rand.NewSource(5))
	for i := 0; i < 4096; i++ {
		n := r.Intn(4096)
		if i < 300 {
			n = i
		}
		if i == 4095 {
			n = 65535
		}
		key := make([]byte, 32)
		nonce := make([]byte, 12)
		aad := make([]byte, r.Intn(129))
		plain := make([]byte, n)
		r.Read(key)
		r.Read(nonce)
		r.Read(aad)
		r.Read(plain)
		a, _ := New(key)
		b, _ := ref.New(key)
		want := b.Seal(nil, nonce, plain, aad)
		buf := make([]byte, 16+n, 16+n+16)
		copy(buf[16:], plain)
		sealed := a.Seal(buf[:16], nonce, buf[16:], aad)
		if !bytes.Equal(sealed[16:], want) {
			t.Fatalf("seal mismatch %d/%d", i, n)
		}
		opened, err := a.Open(sealed[:16], nonce, sealed[16:], aad)
		if err != nil || !bytes.Equal(opened[16:], plain) {
			t.Fatalf("open mismatch %d: %v", i, err)
		}
		bad := append([]byte(nil), want...)
		bad[len(bad)-1] ^= 1
		dst := bytes.Repeat([]byte{0xa5}, n)
		if out, err := a.Open(dst[:0], nonce, bad, aad); err == nil || out != nil {
			t.Fatal("accepted forged tag")
		}
		if !bytes.Equal(dst, make([]byte, n)) {
			t.Fatal("unauthenticated output not cleared")
		}
		out, err := a.Open(nil, nonce, want, aad)
		if err != nil || !bytes.Equal(out, plain) {
			t.Fatal("context reuse after failure", err)
		}
	}
}

// TestConcurrentReuse verifies that concurrent calls keep packet state independent.
func TestConcurrentReuse(t *testing.T) {
	key := make([]byte, 32)
	a, _ := New(key)
	b, _ := ref.New(key)
	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 300; i++ {
				nonce := make([]byte, 12)
				binary.LittleEndian.PutUint64(nonce, uint64(g*300+i))
				plain := bytes.Repeat([]byte{byte(g)}, 1280)
				ct := a.Seal(nil, nonce, plain, nil)
				if !bytes.Equal(ct, b.Seal(nil, nonce, plain, nil)) {
					t.Error("concurrent seal mismatch")
					return
				}
				out, err := a.Open(nil, nonce, ct, nil)
				if err != nil || !bytes.Equal(out, plain) {
					t.Error("concurrent open mismatch")
					return
				}
			}
		}(g)
	}
	wg.Wait()
}

// TestInvalidInputs rejects incorrect keys, nonces and buffer overlap.
func TestInvalidInputs(t *testing.T) {
	for _, n := range []int{0, 1, 31, 33, 64} {
		if _, err := New(make([]byte, n)); err == nil {
			t.Fatal("accepted invalid key")
		}
	}
	a, _ := New(make([]byte, 32))
	if _, err := a.Open(nil, make([]byte, 12), make([]byte, 15), nil); err == nil {
		t.Fatal("accepted short ciphertext")
	}
	for _, f := range []func(){
		func() { a.Seal(nil, make([]byte, 11), nil, nil) },
		func() { a.Open(nil, make([]byte, 13), nil, nil) },
		func() { b := make([]byte, 100); a.Seal(b[1:1], make([]byte, 12), b[:40], nil) },
		func() { b := make([]byte, 100); a.Seal(b[:0], make([]byte, 12), nil, b[:20]) },
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Error("invalid input did not panic")
				}
			}()
			f()
		}()
	}
}

// BenchmarkAEAD compares identical in-place packet operations on both backends.
func BenchmarkAEAD(b *testing.B) {
	for _, size := range []int{64, 1280, 1420, 8192} {
		for _, impl := range []struct {
			name string
			new  func([]byte) (cipher.AEAD, error)
		}{{"Go", ref.New}, {"Native", New}} {
			a, _ := impl.new(make([]byte, 32))
			nonce := make([]byte, 12)
			b.Run(fmt.Sprintf("%s/Seal/%d", impl.name, size), func(b *testing.B) {
				buf := make([]byte, size, size+16)
				b.SetBytes(int64(size))
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					binary.LittleEndian.PutUint64(nonce, uint64(i))
					a.Seal(buf[:0], nonce, buf, nil)
				}
			})
			b.Run(fmt.Sprintf("%s/Open/%d", impl.name, size), func(b *testing.B) {
				ct := a.Seal(nil, nonce, make([]byte, size), nil)
				out := make([]byte, 0, size)
				b.SetBytes(int64(size))
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if _, err := a.Open(out, nonce, ct, nil); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}
