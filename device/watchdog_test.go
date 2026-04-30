/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"testing"
	"time"
)

func newWatchdogTestPeer(tb testing.TB) (*Peer, *recordingBind) {
	tb.Helper()

	peer, bind := newLatencyTestPeer(tb)
	peer.device.peerEvents = make(chan PeerEvent, peerEventQueueSize)
	peer.device.linkWatchdogMultiplier.Store(defaultLinkWatchdogMultiplier)
	peer.persistentKeepaliveInterval.Store(1)
	return peer, bind
}

func drainPeerEvent(tb testing.TB, ch <-chan PeerEvent, typ PeerEventType) {
	tb.Helper()

	select {
	case event := <-ch:
		if event.Type != typ {
			tb.Fatalf("unexpected peer event: got %s want %s", event.Type, typ)
		}
	default:
		tb.Fatalf("expected peer event %s", typ)
	}
}

func TestKickLinkWatchdogArmsProbeAndDeadline(t *testing.T) {
	peer, _ := newWatchdogTestPeer(t)

	peer.kickLinkWatchdog()

	if !peer.timers.linkUp.Load() {
		t.Fatal("expected peer to be marked link-up")
	}
	if !peer.timers.linkWatchdog.IsPending() {
		t.Fatal("expected link watchdog timer to be pending")
	}
	if !peer.timers.linkWatchdogProbe.IsPending() {
		t.Fatal("expected pre-expiry watchdog probe timer to be pending")
	}
	drainPeerEvent(t, peer.device.PeerEvents(), PeerEventUp)
}

func TestExpiredLinkWatchdogProbeSendsProbeWhileLinkUp(t *testing.T) {
	peer, bind := newWatchdogTestPeer(t)
	peer.timers.linkUp.Store(true)

	expiredLinkWatchdogProbe(peer)

	if got := bind.count(MessageLatencyProbeType); got != 1 {
		t.Fatalf("unexpected latency probe count: got %d want 1", got)
	}
}

func TestExpiredLinkWatchdogProbeBypassesActiveLatencyProbe(t *testing.T) {
	peer, bind := newWatchdogTestPeer(t)
	peer.timers.linkUp.Store(true)

	peer.latency.Lock()
	peer.latency.active = true
	peer.latency.token = 42
	peer.latency.Unlock()

	expiredLinkWatchdogProbe(peer)

	if got := bind.count(MessageLatencyProbeType); got != 1 {
		t.Fatalf("unexpected latency probe count with active measurement: got %d want 1", got)
	}
	peer.latency.Lock()
	active := peer.latency.active
	token := peer.latency.token
	peer.latency.Unlock()
	if !active || token != 42 {
		t.Fatalf("watchdog probe changed latency state: active=%v token=%d", active, token)
	}
}

func TestLinkWatchdogDownFiresAtOriginalDeadlineWithoutAck(t *testing.T) {
	peer, bind := newWatchdogTestPeer(t)
	peer.device.linkWatchdogMultiplier.Store(1)

	peer.kickLinkWatchdog()
	drainPeerEvent(t, peer.device.PeerEvents(), PeerEventUp)

	waitForPeerEvent(t, peer.device.PeerEvents(), PeerEventDown, 1500*time.Millisecond)
	if !peer.timers.linkWatchdogProbe.IsPending() && bind.count(MessageLatencyProbeType) == 0 {
		t.Fatal("expected pre-expiry probe before watchdog down")
	}
}

func TestLinkWatchdogProbeAckPreventsOriginalDeadlineDown(t *testing.T) {
	goroutineLeakCheck(t)

	_, _, receiver, _, receiverPeer := setupEstablishedLink(t)
	receiverPeer.persistentKeepaliveInterval.Store(1)
	receiverPeer.device.SetLinkWatchdogMultiplier(1)
	receiverPeer.kickLinkWatchdog()

	assertNoPeerEvent(t, receiver.dev.PeerEvents(), 1200*time.Millisecond)
}

func TestDisabledLinkWatchdogDisablesDeadlineAndProbe(t *testing.T) {
	peer, bind := newWatchdogTestPeer(t)
	peer.device.SetLinkWatchdogMultiplier(linkWatchdogMultiplierDisabled)

	peer.kickLinkWatchdog()

	if peer.timers.linkWatchdog.IsPending() {
		t.Fatal("expected disabled watchdog deadline timer not to be pending")
	}
	if peer.timers.linkWatchdogProbe.IsPending() {
		t.Fatal("expected disabled watchdog probe timer not to be pending")
	}
	if peer.timers.linkUp.Load() {
		t.Fatal("expected disabled watchdog not to mark peer link-up")
	}

	peer.timers.linkUp.Store(true)
	expiredLinkWatchdog(peer)
	expiredLinkWatchdogProbe(peer)

	if got := bind.count(MessageLatencyProbeType); got != 0 {
		t.Fatalf("unexpected latency probe count while disabled: got %d want 0", got)
	}
	if !peer.timers.linkUp.Load() {
		t.Fatal("disabled watchdog should not mark peer down")
	}
}
