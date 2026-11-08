//go:build arm

/* SPDX-License-Identifier: MIT */

package device

import (
	"crypto/cipher"

	aead "golang.zx2c4.com/wireguard/tsasm/arm/chacha20poly1305"
)

// newDataAEAD creates the cipher for WireGuard transport packets on 32-bit ARM.
// ChaCha20 uses NEON when supported and scalar assembly otherwise. Poly1305
// uses scalar assembly. Handshake and cookie ciphers keep x/crypto.
func newDataAEAD(key []byte) (cipher.AEAD, error) { return aead.New(key) }
