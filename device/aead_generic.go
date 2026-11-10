//go:build !arm && !arm64

/* SPDX-License-Identifier: MIT */

package device

import (
	"crypto/cipher"

	aead "golang.org/x/crypto/chacha20poly1305"
)

// newDataAEAD creates the cipher for WireGuard transport packets.
func newDataAEAD(key []byte) (cipher.AEAD, error) { return aead.New(key) }
