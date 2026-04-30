package device

import "time"

const (
	peerEventQueueSize             = 1024
	defaultLinkWatchdogMultiplier  = 3
	linkWatchdogMultiplierDisabled = 0
)

type PeerEventType uint8

const (
	PeerEventUp PeerEventType = iota
	PeerEventDown
)

func (pet PeerEventType) String() string {
	switch pet {
	case PeerEventUp:
		return "up"
	case PeerEventDown:
		return "down"
	default:
		return "unknown"
	}
}

type PeerEvent struct {
	Peer *Peer
	Key  NoisePublicKey
	Type PeerEventType
}

// PeerEvents returns a channel that emits PeerEvent values when peers go up
// or down according to the link watchdog. The channel is buffered to avoid
// blocking the device's operation, and events may be dropped if the buffer
// fills up.
func (device *Device) PeerEvents() <-chan PeerEvent {
	return device.peerEvents
}

// SetLinkWatchdogMultiplier controls how many keepalive intervals without
// receiving a transport packet are tolerated before a PeerDown event is
// emitted. A value of 0 disables the watchdog.
func (device *Device) SetLinkWatchdogMultiplier(multiplier uint32) {
	if multiplier == linkWatchdogMultiplierDisabled {
		device.linkWatchdogMultiplier.Store(linkWatchdogMultiplierDisabled)
		device.log.Verbosef("Disabled link watchdog")
		return
	}
	device.linkWatchdogMultiplier.Store(multiplier)
	device.log.Verbosef("Enabled link watchdog with multiplier %d", multiplier)
}

// emitPeerEvent sends a PeerEvent to the device's peerEvents channel,
// dropping it if the channel is full.
func (device *Device) emitPeerEvent(event PeerEvent) {
	if device == nil || device.peerEvents == nil {
		return
	}
	device.log.Verbosef("%s - Link is %s", event.Peer, event.Type.String())
	select {
	case device.peerEvents <- event:
	default:
		device.log.Errorf("%s - Dropping peer event: channel full", event.Peer)
	}
}

// expiredLinkWatchdog is called when a peer's link watchdog timer expires.  It
// marks the peer as down and emits a PeerDown event if the peer was previously
// up. Peers that receive a transport packet just before the watchdog expires
// can avoid being marked down by sending a link watchdog probe in
// expiredLinkWatchdogProbe.
func expiredLinkWatchdog(peer *Peer) {
	if !peer.timersActive() || peer.linkWatchdogInterval() == 0 {
		return
	}
	if !peer.timers.linkUp.Swap(false) {
		return
	}
	peer.timers.linkWatchdogProbe.Del()
	peer.device.emitPeerEvent(PeerEvent{Type: PeerEventDown, Peer: peer, Key: peerPublicKey(peer)})
}

// expiredLinkWatchdogProbe is called before the link watchdog expires. It sends
// a one-shot latency probe so mobile peers can prove liveness before the hard
// watchdog deadline without extending that deadline.
func expiredLinkWatchdogProbe(peer *Peer) {
	if !peer.timersActive() || peer.linkWatchdogInterval() == 0 || !peer.timers.linkUp.Load() {
		return
	}
	peer.sendLinkWatchdogProbe()
}

// notePeerClosing marks the peer down immediately after receiving an
// authenticated peer-closing notice from the remote side.
func (peer *Peer) notePeerClosing() {
	if peer == nil || peer.device == nil {
		return
	}
	if peer.timers.linkUp.Swap(false) {
		peer.timers.linkWatchdogProbe.Del()
		peer.device.emitPeerEvent(PeerEvent{Type: PeerEventDown, Peer: peer, Key: peerPublicKey(peer)})
	}
}

// kickLinkWatchdog is called when a transport packet is received from the
// peer.
func (peer *Peer) kickLinkWatchdog() {
	if !peer.timersActive() {
		return
	}

	interval := peer.linkWatchdogInterval()
	if interval == 0 {
		peer.timers.linkWatchdog.Del()
		peer.timers.linkWatchdogProbe.Del()
		return
	}

	if !peer.timers.linkUp.Swap(true) {
		peer.device.emitPeerEvent(PeerEvent{Type: PeerEventUp, Peer: peer, Key: peerPublicKey(peer)})
	}

	peer.timers.linkWatchdog.Mod(interval)
	if probeInterval := linkWatchdogProbeInterval(interval); probeInterval > 0 {
		peer.timers.linkWatchdogProbe.Mod(probeInterval)
	} else {
		peer.timers.linkWatchdogProbe.Del()
	}
}

// linkWatchdogInterval returns the current link watchdog interval for the peer.
func (peer *Peer) linkWatchdogInterval() time.Duration {
	multiplier := peer.device.linkWatchdogMultiplier.Load()
	if multiplier == linkWatchdogMultiplierDisabled {
		return 0
	}

	interval := KeepaliveTimeout
	if keepalive := peer.persistentKeepaliveInterval.Load(); keepalive > 0 {
		interval = time.Duration(keepalive) * time.Second
	}

	return interval * time.Duration(multiplier)
}

// linkWatchdogProbeInterval returns the pre-expiry active probe delay for a
// full watchdog interval.
func linkWatchdogProbeInterval(interval time.Duration) time.Duration {
	if interval <= 0 {
		return 0
	}
	return interval * 2 / 3
}

// sendLinkWatchdogProbe sends a liveness-only latency probe without touching
// latency measurement state. The received ack still kicks the watchdog in the
// normal receive path.
func (peer *Peer) sendLinkWatchdogProbe() bool {
	if peer == nil || peer.device == nil {
		return false
	}

	token := peer.device.latencyProbeSeq.Add(1)
	sent, err := peer.sendControlPacket(MessageLatencyProbeType, encodeLatencyToken(token))
	if err != nil {
		peer.device.log.Verbosef("%v - Failed to send link watchdog probe: %v", peer, err)
	}
	return sent && err == nil
}

// peerPublicKey returns the peer's static public key.
func peerPublicKey(peer *Peer) NoisePublicKey {
	peer.handshake.mutex.RLock()
	defer peer.handshake.mutex.RUnlock()
	return peer.handshake.remoteStatic
}
