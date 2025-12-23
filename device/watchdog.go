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

// expiredLinkWatchdog is called when a peer's link watchdog timer expires.
func expiredLinkWatchdog(peer *Peer) {
	if peer.timersActive() && peer.timers.linkUp.Swap(false) {
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
		return
	}

	if !peer.timers.linkUp.Swap(true) {
		peer.device.emitPeerEvent(PeerEvent{Type: PeerEventUp, Peer: peer, Key: peerPublicKey(peer)})
	}

	peer.timers.linkWatchdog.Mod(interval)
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

// peerPublicKey returns the peer's static public key.
func peerPublicKey(peer *Peer) NoisePublicKey {
	peer.handshake.mutex.RLock()
	defer peer.handshake.mutex.RUnlock()
	return peer.handshake.remoteStatic
}
