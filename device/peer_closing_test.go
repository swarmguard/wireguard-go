/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"testing"
	"time"
)

func singlePeer(tb testing.TB, dev *Device) *Peer {
	tb.Helper()

	dev.peers.RLock()
	defer dev.peers.RUnlock()

	if len(dev.peers.keyMap) != 1 {
		tb.Fatalf("expected exactly one peer, got %d", len(dev.peers.keyMap))
	}
	for _, peer := range dev.peers.keyMap {
		return peer
	}
	tb.Fatal("expected a peer")
	return nil
}

func waitForPeerEvent(tb testing.TB, ch <-chan PeerEvent, typ PeerEventType, timeout time.Duration) PeerEvent {
	tb.Helper()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	for {
		select {
		case event := <-ch:
			if event.Type == typ {
				return event
			}
		case <-timer.C:
			tb.Fatalf("timed out waiting for peer event %s", typ)
		}
	}
}

func assertNoPeerEvent(tb testing.TB, ch <-chan PeerEvent, timeout time.Duration) {
	tb.Helper()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case event := <-ch:
		tb.Fatalf("unexpected peer event %s", event.Type)
	case <-timer.C:
	}
}

func assertNoInboundPacket(tb testing.TB, peer testPeer, timeout time.Duration) {
	tb.Helper()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case packet := <-peer.tun.Inbound:
		tb.Fatalf("unexpected packet delivered to TUN: %d bytes", len(packet))
	case <-timer.C:
	}
}

func setupEstablishedLink(tb testing.TB) (testPair, testPeer, testPeer, *Peer, *Peer) {
	tb.Helper()

	pair := genTestPair(tb, false)
	receiver := pair[0]
	sender := pair[1]

	pair.Send(tb, Ping, nil)
	waitForPeerEvent(tb, receiver.dev.PeerEvents(), PeerEventUp, time.Second)

	senderPeer := singlePeer(tb, sender.dev)
	receiverPeer := singlePeer(tb, receiver.dev)
	if !receiverPeer.timers.linkUp.Load() {
		tb.Fatal("receiver peer did not become link-up")
	}

	return pair, sender, receiver, senderPeer, receiverPeer
}

func TestPeerClosingNoticeMarksPeerDownWithoutTouchingTUN(t *testing.T) {
	goroutineLeakCheck(t)

	_, sender, receiver, senderPeer, receiverPeer := setupEstablishedLink(t)
	senderPeer.SendPeerClosingNotice()

	event := waitForPeerEvent(t, receiver.dev.PeerEvents(), PeerEventDown, time.Second)
	if event.Peer != receiverPeer {
		t.Fatalf("unexpected peer in down event")
	}
	if receiverPeer.timers.linkUp.Load() {
		t.Fatal("receiver peer still marked link-up after peer-closing notice")
	}

	assertNoInboundPacket(t, receiver, 200*time.Millisecond)
	_ = sender
}

func TestDeviceCloseSendsPeerClosingNotice(t *testing.T) {
	goroutineLeakCheck(t)

	_, sender, receiver, _, receiverPeer := setupEstablishedLink(t)
	sender.dev.Close()

	event := waitForPeerEvent(t, receiver.dev.PeerEvents(), PeerEventDown, time.Second)
	if event.Peer != receiverPeer {
		t.Fatalf("unexpected peer in down event")
	}
}

func TestRemovePeerSendsPeerClosingNotice(t *testing.T) {
	goroutineLeakCheck(t)

	_, sender, receiver, _, receiverPeer := setupEstablishedLink(t)
	sender.dev.RemovePeer(receiver.dev.staticIdentity.publicKey)

	event := waitForPeerEvent(t, receiver.dev.PeerEvents(), PeerEventDown, time.Second)
	if event.Peer != receiverPeer {
		t.Fatalf("unexpected peer in down event")
	}

	if peer := sender.dev.LookupPeer(receiver.dev.staticIdentity.publicKey); peer != nil {
		t.Fatal("peer still present after RemovePeer")
	}
}

func TestUnknownControlMessageIsIgnored(t *testing.T) {
	goroutineLeakCheck(t)

	_, _, receiver, senderPeer, receiverPeer := setupEstablishedLink(t)
	if _, err := senderPeer.sendControlPacket(MessagePeerClosingType+100, nil); err != nil {
		t.Fatalf("failed to send unknown control packet: %v", err)
	}

	assertNoPeerEvent(t, receiver.dev.PeerEvents(), 200*time.Millisecond)
	if !receiverPeer.timers.linkUp.Load() {
		t.Fatal("receiver peer unexpectedly went down after unknown control packet")
	}
}
