/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 SwarmGuard. All Rights Reserved.
 */

package device

import "time"

// PeerStats contains independent copies of one peer's traffic counters and
// latest successful handshake time. A zero LastHandshake means no handshake
// has completed.
type PeerStats struct {
	PublicKey     NoisePublicKey
	RxBytes       uint64
	TxBytes       uint64
	LastHandshake time.Time
}

// PeerStats returns statistics for the current peers in unspecified order.
// It serializes with UAPI configuration and peer-map changes, and loads each
// counter atomically. Traffic can advance during collection, so the values
// are not a simultaneous snapshot of all counters. No peer references or
// configuration secrets are returned.
func (device *Device) PeerStats() []PeerStats {
	device.ipcMutex.RLock()
	defer device.ipcMutex.RUnlock()
	device.peers.RLock()
	defer device.peers.RUnlock()

	stats := make([]PeerStats, 0, len(device.peers.keyMap))
	for publicKey, peer := range device.peers.keyMap {
		entry := PeerStats{
			PublicKey: publicKey,
			RxBytes:   peer.rxBytes.Load(),
			TxBytes:   peer.txBytes.Load(),
		}
		if nano := peer.lastHandshakeNano.Load(); nano != 0 {
			entry.LastHandshake = time.Unix(0, nano).UTC()
		}
		stats = append(stats, entry)
	}
	return stats
}
