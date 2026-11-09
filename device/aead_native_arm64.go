//go:build arm64

/* SPDX-License-Identifier: MIT */

package device

import (
	"crypto/cipher"

	aead "golang.zx2c4.com/wireguard/tsasm/arm64/chacha20poly1305"
)

// newDataAEAD creates the native ARM64 cipher for WireGuard transport packets.
func newDataAEAD(key []byte) (cipher.AEAD, error) { return aead.New(key) }
