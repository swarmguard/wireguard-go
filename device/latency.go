/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"encoding/binary"
	"time"
)

var (
	latencyProbeInterval    = 15 * time.Second
	latencyProbeTimeout     = 5 * time.Second
	latencyProbeRetryDelays = []time.Duration{
		250 * time.Millisecond,
		500 * time.Millisecond,
		1 * time.Second,
	}
)

func encodeLatencyToken(token uint64) []byte {
	payload := make([]byte, MessageLatencyTokenSize)
	binary.LittleEndian.PutUint64(payload, token)
	return payload
}

func decodeLatencyToken(payload []byte) (uint64, bool) {
	if len(payload) != MessageLatencyTokenSize {
		return 0, false
	}
	return binary.LittleEndian.Uint64(payload), true
}

func (peer *Peer) Latency() (time.Duration, bool) {
	if peer == nil {
		return 0, false
	}
	if !peer.latency.valid.Load() {
		return 0, false
	}
	return time.Duration(peer.latency.lastNanos.Load()), true
}

func (peer *Peer) storeLatency(value time.Duration) {
	if peer == nil {
		return
	}
	peer.latency.lastNanos.Store(int64(value))
	peer.latency.lastAtNano.Store(time.Now().UnixNano())
	peer.latency.valid.Store(true)
}

func (peer *Peer) resetLatencyProbeState() {
	if peer == nil {
		return
	}
	if peer.timers.latencyProbeRetry != nil {
		peer.timers.latencyProbeRetry.Del()
	}
	peer.latency.Lock()
	peer.latency.active = false
	peer.latency.pending = false
	peer.latency.token = 0
	peer.latency.sentAt = time.Time{}
	peer.latency.retryAttempt = 0
	peer.latency.Unlock()
}

func (peer *Peer) triggerLatencyProbe() bool {
	return peer.triggerLatencyProbeWithRetry(true, false)
}

func (peer *Peer) triggerLatencyProbeWithRetry(allowRetry, isRetryAttempt bool) bool {
	if peer == nil || peer.device == nil {
		return false
	}

	if !peer.isRunning.Load() || !peer.device.isUp() {
		return false
	}

	peer.latency.Lock()
	if allowRetry && !isRetryAttempt {
		peer.latency.retryAttempt = 0
		if peer.timers.latencyProbeRetry != nil {
			peer.timers.latencyProbeRetry.Del()
		}
	}
	if peer.latency.active {
		peer.latency.pending = true
		peer.latency.Unlock()
		return true
	}

	token := peer.device.latencyProbeSeq.Add(1)
	sentAt := time.Now()
	peer.latency.active = true
	peer.latency.pending = false
	peer.latency.token = token
	peer.latency.sentAt = sentAt
	peer.latency.Unlock()

	sent, err := peer.sendControlPacket(MessageLatencyProbeType, encodeLatencyToken(token))
	if err != nil {
		peer.device.log.Verbosef("%v - Failed to send latency probe: %v", peer, err)
	}
	if !sent || err != nil {
		peer.completeLatencyProbe(token, false)
		if allowRetry {
			return peer.scheduleLatencyProbeRetry()
		}
		return false
	}
	peer.clearLatencyProbeRetry()

	if latencyProbeTimeout > 0 {
		peer.timers.latencyProbeTimeout.Mod(latencyProbeTimeout)
	}
	return true
}

func (peer *Peer) handleLatencyProbe(token uint64) {
	if peer == nil || peer.device == nil {
		return
	}

	sent, err := peer.sendControlPacket(MessageLatencyAckType, encodeLatencyToken(token))
	if err != nil {
		peer.device.log.Verbosef("%v - Failed to send latency ack: %v", peer, err)
	}
	if !sent || err != nil {
		peer.device.log.Verbosef("%v - Skipped latency ack: no active session", peer)
		return
	}
}

func (peer *Peer) handleLatencyAck(token uint64) {
	if peer == nil {
		return
	}

	peer.latency.Lock()
	if !peer.latency.active || peer.latency.token != token {
		peer.latency.Unlock()
		return
	}
	sentAt := peer.latency.sentAt
	peer.latency.Unlock()

	halfRTT := time.Since(sentAt) / 2
	peer.storeLatency(halfRTT)
	peer.completeLatencyProbe(token, true)
}

func (peer *Peer) handleLatencyProbeTimeout() {
	if peer == nil {
		return
	}

	peer.latency.Lock()
	if !peer.latency.active {
		peer.latency.Unlock()
		return
	}
	token := peer.latency.token
	peer.latency.Unlock()

	peer.completeLatencyProbe(token, true)
}

func (peer *Peer) completeLatencyProbe(token uint64, stopTimer bool) {
	if peer == nil {
		return
	}

	if stopTimer && peer.timers.latencyProbeTimeout != nil {
		peer.timers.latencyProbeTimeout.Del()
	}

	followUp := false
	peer.latency.Lock()
	if !peer.latency.active || peer.latency.token != token {
		peer.latency.Unlock()
		return
	}
	followUp = peer.latency.pending
	peer.latency.active = false
	peer.latency.pending = false
	peer.latency.token = 0
	peer.latency.sentAt = time.Time{}
	peer.latency.Unlock()

	if followUp {
		peer.triggerLatencyProbeWithRetry(true, false)
	}
}

func (peer *Peer) scheduleLatencyProbeRetry() bool {
	if peer == nil || !peer.timersActive() || peer.timers.latencyProbeRetry == nil {
		return false
	}

	peer.latency.Lock()
	attempt := peer.latency.retryAttempt
	if attempt < 0 || attempt >= len(latencyProbeRetryDelays) {
		peer.latency.Unlock()
		return false
	}
	delay := latencyProbeRetryDelays[attempt]
	peer.latency.retryAttempt++
	peer.latency.Unlock()

	peer.timers.latencyProbeRetry.Mod(delay)
	return true
}

func (peer *Peer) clearLatencyProbeRetry() {
	if peer == nil {
		return
	}

	if peer.timers.latencyProbeRetry != nil {
		peer.timers.latencyProbeRetry.Del()
	}
	peer.latency.Lock()
	peer.latency.retryAttempt = 0
	peer.latency.Unlock()
}

func expiredLatencyProbePeriodic(peer *Peer) {
	if peer == nil {
		return
	}

	if peer.timersActive() && latencyProbeInterval > 0 {
		peer.timers.latencyProbePeriodic.Mod(latencyProbeInterval)
	}

	if peer.timersActive() && peer.timers.linkUp.Load() {
		peer.triggerLatencyProbeWithRetry(false, false)
	}
}

func expiredLatencyProbeRetry(peer *Peer) {
	if peer == nil {
		return
	}
	peer.triggerLatencyProbeWithRetry(true, true)
}

func expiredLatencyProbeTimeout(peer *Peer) {
	peer.handleLatencyProbeTimeout()
}
