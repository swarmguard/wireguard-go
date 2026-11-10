// Copyright 2026 SwarmGuard contributors. All rights reserved.
// Use of this source code is governed by the BSD-style license in the repository-root LICENSE file.

//go:build arm64 && gc && !purego

package poly1305

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"math/rand"
	"testing"
)

// TestUpdateBlocksDifferential checks carry propagation from nonzero states.
func TestUpdateBlocksDifferential(t *testing.T) {
	r := rand.New(rand.NewSource(5))
	for trial := 0; trial < 20000; trial++ {
		var key [32]byte
		r.Read(key[:])
		var a macState
		initialize(&key, &a)
		a.h = [3]uint64{r.Uint64(), r.Uint64(), uint64(r.Intn(6))}
		if trial%4 == 0 {
			a.h = [3]uint64{^uint64(0), ^uint64(0), 5}
		}
		if trial%4 == 1 {
			a.r = [2]uint64{rMask0, rMask1}
		}
		b := a
		data := make([]byte, 16*(1+r.Intn(64)))
		r.Read(data)
		if trial%3 == 0 {
			for i := range data {
				data[i] = 255
			}
		}
		updateBlocks(&a, data)
		updateGeneric(&b, data)
		if a != b {
			t.Fatalf("state mismatch at trial %d: %#v != %#v", trial, a, b)
		}
	}
}

// FuzzMAC compares whole and arbitrarily split messages against the reference.
func FuzzMAC(f *testing.F) {
	for _, n := range []int{0, 1, 15, 16, 17, 31, 32, 63, 64, 65, 127, 128, 255, 256, 1280, 65535} {
		f.Add(bytes.Repeat([]byte{255}, n), uint64(n))
	}
	f.Fuzz(func(t *testing.T, msg []byte, seed uint64) {
		if len(msg) > 65536 {
			t.Skip()
		}
		var kb [8]byte
		binary.LittleEndian.PutUint64(kb[:], seed)
		key := sha256.Sum256(kb[:])
		var got, want [16]byte
		Sum(&got, msg, &key)
		sumGeneric(&want, msg, &key)
		if got != want {
			t.Fatal("whole-message mismatch")
		}
		h := New(&key)
		offset := 0
		for offset < len(msg) {
			n := int(seed%31) + 1
			if n > len(msg)-offset {
				n = len(msg) - offset
			}
			h.Write(msg[offset : offset+n])
			offset += n
			seed = seed*6364136223846793005 + 1
		}
		if !bytes.Equal(h.Sum(nil), want[:]) {
			t.Fatal("split-message mismatch")
		}
	})
}
