/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import "testing"

func TestPeerLogLabelUsesMetadata(t *testing.T) {
	peer := &Peer{}
	peer.SetUserData(PeerLogMetadata{Name: "demo1", Serial: "serial-a"})

	if got, want := peerLogLabel(peer), "demo1 (serial-a)"; got != want {
		t.Fatalf("peerLogLabel() = %q, want %q", got, want)
	}
}

func TestPacketKindCountsClassifiesWireGuardPackets(t *testing.T) {
	transportPacket := make([]byte, MessageKeepaliveSize+1)
	transportPacket[0] = MessageTransportType
	keepalivePacket := make([]byte, MessageKeepaliveSize)
	keepalivePacket[0] = MessageTransportType
	latencyProbePacket := make([]byte, MessageLatencyProbeSize)
	latencyProbePacket[0] = MessageLatencyProbeType
	latencyAckPacket := make([]byte, MessageLatencyAckSize)
	latencyAckPacket[0] = MessageLatencyAckType
	peerClosingPacket := make([]byte, MessagePeerClosingSize)
	peerClosingPacket[0] = MessagePeerClosingType

	data, keepalive, latencyProbe, latencyAck, peerClosing, other := packetKindCounts([][]byte{
		transportPacket,
		keepalivePacket,
		latencyProbePacket,
		latencyAckPacket,
		peerClosingPacket,
		[]byte{99, 0, 0, 0},
	})

	if data != 1 || keepalive != 1 || latencyProbe != 1 || latencyAck != 1 || peerClosing != 1 || other != 1 {
		t.Fatalf("unexpected counts: data=%d keepalive=%d latencyProbe=%d latencyAck=%d peerClosing=%d other=%d", data, keepalive, latencyProbe, latencyAck, peerClosing, other)
	}
}
