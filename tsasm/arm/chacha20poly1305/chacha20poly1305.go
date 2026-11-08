// SPDX-License-Identifier: BSD-3-Clause

//go:build arm

// Package chacha20poly1305 provides a ChaCha20-Poly1305 AEAD built
// from the hand-ported ChaCha20 and Poly1305 kernels in
// tsasm/arm/chacha20 and tsasm/arm/poly1305. It only builds on
// GOARCH=arm; other architectures should use
// golang.org/x/crypto/chacha20poly1305.
package chacha20poly1305

import (
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"unsafe"

	chacha "golang.zx2c4.com/wireguard/tsasm/arm/chacha20"
	"golang.zx2c4.com/wireguard/tsasm/arm/poly1305"
)

const (
	KeySize   = 32
	NonceSize = 12
	Overhead  = 16
)

type aead struct {
	key [KeySize]byte
}

// New returns a chacha20poly1305 AEAD with the given 32-byte key.
func New(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, errors.New("chacha20poly1305: bad key length")
	}
	a := &aead{}
	copy(a.key[:], key)
	return a, nil
}

func (a *aead) NonceSize() int { return NonceSize }
func (a *aead) Overhead() int  { return Overhead }

func (a *aead) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(nonce) != NonceSize {
		panic("chacha20poly1305: bad nonce length")
	}
	if uint64(len(plaintext)) > (1<<38)-64 {
		panic("chacha20poly1305: plaintext too large")
	}
	ret, out := sliceForAppend(dst, len(plaintext)+Overhead)
	checkOverlap(out, plaintext, additionalData)

	var nonceArr [chacha.NonceSize]byte
	copy(nonceArr[:], nonce)

	// Derive the Poly1305 one-time key from the first 32 bytes of the
	// ChaCha20 keystream at counter 0, then encrypt at counter 1.
	var (
		zeros   [64]byte
		polyBuf [64]byte
		polyKey [32]byte
	)
	chacha.XORKeyStream(polyBuf[:], zeros[:], &a.key, &nonceArr, 0)
	copy(polyKey[:], polyBuf[:32])
	chacha.XORKeyStream(out[:len(plaintext)], plaintext, &a.key, &nonceArr, 1)

	tag := computeTag(additionalData, out[:len(plaintext)], &polyKey)
	copy(out[len(plaintext):], tag[:])
	return ret
}

func (a *aead) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != NonceSize {
		panic("chacha20poly1305: bad nonce length")
	}
	if len(ciphertext) < Overhead {
		return nil, errors.New("chacha20poly1305: ciphertext too short")
	}
	if uint64(len(ciphertext)) > (1<<38)-48 {
		panic("chacha20poly1305: ciphertext too large")
	}
	ctLen := len(ciphertext) - Overhead
	ct := ciphertext[:ctLen]
	receivedTag := ciphertext[ctLen:]

	var nonceArr [chacha.NonceSize]byte
	copy(nonceArr[:], nonce)

	var (
		zeros   [64]byte
		polyBuf [64]byte
		polyKey [32]byte
	)
	chacha.XORKeyStream(polyBuf[:], zeros[:], &a.key, &nonceArr, 0)
	copy(polyKey[:], polyBuf[:32])

	ret, out := sliceForAppend(dst, ctLen)
	checkOverlap(out, ct, additionalData)
	expectedTag := computeTag(additionalData, ct, &polyKey)
	if subtle.ConstantTimeCompare(receivedTag, expectedTag[:]) != 1 {
		clear(out)
		return nil, errors.New("chacha20poly1305: message authentication failed")
	}

	chacha.XORKeyStream(out, ct, &a.key, &nonceArr, 1)
	return ret, nil
}

var zeros16 [16]byte

// computeTag streams (aad || pad16 || ct || pad16 || u64le(|aad|) ||
// u64le(|ct|)) through a stack-allocated Poly1305 MAC.
func computeTag(aad, ct []byte, polyKey *[32]byte) [16]byte {
	var mac poly1305.MAC
	mac.Init(polyKey)
	mac.Write(aad)
	if rem := len(aad) % 16; rem != 0 {
		mac.Write(zeros16[:16-rem])
	}
	mac.Write(ct)
	if rem := len(ct) % 16; rem != 0 {
		mac.Write(zeros16[:16-rem])
	}
	var lenBuf [16]byte
	binary.LittleEndian.PutUint64(lenBuf[0:8], uint64(len(aad)))
	binary.LittleEndian.PutUint64(lenBuf[8:16], uint64(len(ct)))
	mac.Write(lenBuf[:])

	var tag [16]byte
	mac.Sum(&tag)
	return tag
}

func sliceForAppend(dst []byte, n int) (head, tail []byte) {
	if total := len(dst) + n; cap(dst) >= total {
		head = dst[:total]
	} else {
		head = make([]byte, total)
		copy(head, dst)
	}
	tail = head[len(dst):]
	return
}

// checkOverlap preserves the x/crypto AEAD input and AAD overlap checks.
func checkOverlap(out, in, aad []byte) {
	if len(out) > 0 && len(in) > 0 && &out[0] != &in[0] && overlaps(out, in) {
		panic("chacha20poly1305: invalid buffer overlap of output and input")
	}
	if overlaps(out, aad) {
		panic("chacha20poly1305: invalid buffer overlap of output and additional data")
	}
}

// overlaps reports whether nonempty byte ranges share storage.
func overlaps(a, b []byte) bool {
	return len(a) > 0 && len(b) > 0 && uintptr(unsafe.Pointer(&a[0])) <= uintptr(unsafe.Pointer(&b[len(b)-1])) && uintptr(unsafe.Pointer(&b[0])) <= uintptr(unsafe.Pointer(&a[len(a)-1]))
}
