/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"crypto/cipher"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.zx2c4.com/wireguard/conn"
)

func waitForPeerLatency(tb testing.TB, dev *Device, pk NoisePublicKey, timeout time.Duration) time.Duration {
	tb.Helper()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()

	for {
		if latency, ok := dev.PeerLatency(pk); ok {
			return latency
		}

		select {
		case <-ticker.C:
		case <-timer.C:
			tb.Fatalf("timed out waiting for peer latency sample")
		}
	}
}

func waitForBindCount(tb testing.TB, bind *recordingBind, msgType uint32, want int, timeout time.Duration) {
	tb.Helper()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()

	for {
		if bind.count(msgType) >= want {
			return
		}

		select {
		case <-ticker.C:
		case <-timer.C:
			tb.Fatalf("timed out waiting for %d packets of type %d, got %d", want, msgType, bind.count(msgType))
		}
	}
}

type recordingBind struct {
	sendTypes []uint32
	sendErr   error
}

func (b *recordingBind) Open(port uint16) ([]conn.ReceiveBorrowedFunc, uint16, error) {
	return nil, port, nil
}
func (b *recordingBind) Close() error                                  { return nil }
func (b *recordingBind) SetMark(mark uint32) error                     { return nil }
func (b *recordingBind) ParseEndpoint(s string) (conn.Endpoint, error) { return &DummyEndpoint{}, nil }
func (b *recordingBind) BatchSize() int                                { return 1 }
func (b *recordingBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	if b.sendErr != nil {
		return b.sendErr
	}
	for _, buf := range bufs {
		if len(buf) >= 4 {
			b.sendTypes = append(b.sendTypes, uint32(buf[0])|uint32(buf[1])<<8|uint32(buf[2])<<16|uint32(buf[3])<<24)
		}
	}
	return nil
}

func (b *recordingBind) count(msgType uint32) int {
	total := 0
	for _, typ := range b.sendTypes {
		if typ == msgType {
			total++
		}
	}
	return total
}

func newTestAEAD(tb testing.TB) cipher.AEAD {
	tb.Helper()

	aead, err := chacha20poly1305.New(make([]byte, chacha20poly1305.KeySize))
	if err != nil {
		tb.Fatalf("chacha20poly1305.New: %v", err)
	}
	return aead
}

func newLatencyTestPeer(tb testing.TB) (*Peer, *recordingBind) {
	tb.Helper()

	bind := &recordingBind{}
	peer := &Peer{}
	peer.device = &Device{
		log:    NewLogger(LogLevelError, "test: "),
		closed: make(chan struct{}),
	}
	peer.device.state.state.Store(uint32(deviceStateUp))
	peer.device.net.bind = bind
	peer.endpoint.val = &DummyEndpoint{}
	peer.isRunning.Store(true)
	peer.timersInit()
	tb.Cleanup(peer.timersStop)

	peer.keypairs.current = &Keypair{
		send:        newTestAEAD(tb),
		created:     time.Now(),
		remoteIndex: 1,
	}

	return peer, bind
}

func TestLatencyProbeStoresSampleWithoutTouchingTUN(t *testing.T) {
	goroutineLeakCheck(t)

	_, sender, receiver, senderPeer, receiverPeer := setupEstablishedLink(t)
	peerKey := receiver.dev.staticIdentity.publicKey

	if _, ok := sender.dev.PeerLatency(peerKey); ok {
		t.Fatal("unexpected latency sample before probing")
	}
	if !sender.dev.TriggerLatencyProbeToPeer(peerKey) {
		t.Fatal("expected latency probe to be queued")
	}

	latency := waitForPeerLatency(t, sender.dev, peerKey, time.Second)
	if latency <= 0 {
		t.Fatalf("expected positive latency sample, got %s", latency)
	}

	_ = senderPeer
	_ = receiverPeer

	assertNoInboundPacket(t, sender, 200*time.Millisecond)
	assertNoInboundPacket(t, receiver, 200*time.Millisecond)
}

func TestLatencyProbeTimeoutKeepsLastSample(t *testing.T) {
	goroutineLeakCheck(t)

	previousTimeout := latencyProbeTimeout
	latencyProbeTimeout = 50 * time.Millisecond
	t.Cleanup(func() { latencyProbeTimeout = previousTimeout })

	_, sender, receiver, _, _ := setupEstablishedLink(t)
	peerKey := receiver.dev.staticIdentity.publicKey

	if !sender.dev.TriggerLatencyProbeToPeer(peerKey) {
		t.Fatal("expected initial latency probe to be queued")
	}
	first := waitForPeerLatency(t, sender.dev, peerKey, time.Second)

	receiver.dev.RemovePeer(sender.dev.staticIdentity.publicKey)

	if !sender.dev.TriggerLatencyProbeToPeer(peerKey) {
		t.Fatal("expected timeout latency probe to be queued")
	}
	time.Sleep(latencyProbeTimeout + 50*time.Millisecond)

	second, ok := sender.dev.PeerLatency(peerKey)
	if !ok {
		t.Fatal("expected latency sample to remain after timeout")
	}
	if second != first {
		t.Fatalf("expected previous latency sample to be preserved, got %s want %s", second, first)
	}
}

func TestLatencyProbePendingFollowUpSendsExactlyOneAdditionalProbe(t *testing.T) {
	previousTimeout := latencyProbeTimeout
	latencyProbeTimeout = 20 * time.Millisecond
	t.Cleanup(func() { latencyProbeTimeout = previousTimeout })

	peer, bind := newLatencyTestPeer(t)

	if !peer.triggerLatencyProbe() {
		t.Fatal("expected first latency probe trigger to succeed")
	}
	if !peer.triggerLatencyProbe() {
		t.Fatal("expected second latency probe trigger to be queued as pending")
	}

	time.Sleep(3 * latencyProbeTimeout)

	if got := bind.count(MessageLatencyProbeType); got != 2 {
		t.Fatalf("unexpected latency probe send count: got %d want 2", got)
	}
}

func TestLatencyProbeRetriesShortlyWhenSessionIsNotReady(t *testing.T) {
	previousRetryDelays := latencyProbeRetryDelays
	latencyProbeRetryDelays = []time.Duration{
		20 * time.Millisecond,
		40 * time.Millisecond,
	}
	t.Cleanup(func() { latencyProbeRetryDelays = previousRetryDelays })

	peer, bind := newLatencyTestPeer(t)

	peer.keypairs.Lock()
	peer.keypairs.current = nil
	peer.keypairs.Unlock()

	if !peer.triggerLatencyProbe() {
		t.Fatal("expected latency probe trigger to schedule a retry")
	}
	if got := bind.count(MessageLatencyProbeType); got != 0 {
		t.Fatalf("expected no immediate probe send without a keypair, got %d", got)
	}

	time.Sleep(5 * time.Millisecond)

	peer.keypairs.Lock()
	peer.keypairs.current = &Keypair{
		send:        newTestAEAD(t),
		created:     time.Now(),
		remoteIndex: 1,
	}
	peer.keypairs.Unlock()

	waitForBindCount(t, bind, MessageLatencyProbeType, 1, 200*time.Millisecond)
}

func TestPeriodicLatencyProbeRunsOnlyWhileLinkUp(t *testing.T) {
	goroutineLeakCheck(t)

	previousInterval := latencyProbeInterval
	previousTimeout := latencyProbeTimeout
	latencyProbeInterval = 30 * time.Millisecond
	latencyProbeTimeout = 100 * time.Millisecond
	t.Cleanup(func() {
		latencyProbeInterval = previousInterval
		latencyProbeTimeout = previousTimeout
	})

	pair := genTestPair(t, false)
	peerKey := pair[1].dev.staticIdentity.publicKey

	time.Sleep(3 * latencyProbeInterval)
	if _, ok := pair[0].dev.PeerLatency(peerKey); ok {
		t.Fatal("unexpected latency sample before link-up")
	}

	pair.Send(t, Ping, nil)
	latency := waitForPeerLatency(t, pair[0].dev, peerKey, time.Second)
	if latency <= 0 {
		t.Fatalf("expected positive periodic latency sample, got %s", latency)
	}
}
