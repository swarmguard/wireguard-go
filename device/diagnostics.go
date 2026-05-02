/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"encoding/binary"
	"fmt"
	"time"
)

const peerDiagnosticsLogInterval = 5 * time.Second

// PeerLogMetadata carries higher-level peer identity for diagnostics. Callers
// may attach it with Peer.SetUserData.
type PeerLogMetadata struct {
	Name      string
	Serial    string
	PublicKey string
}

func peerLogLabel(peer *Peer) string {
	if peer == nil {
		return "<nil peer>"
	}
	if metadata, ok := peer.UserData().(PeerLogMetadata); ok {
		switch {
		case metadata.Name != "" && metadata.Serial != "":
			return fmt.Sprintf("%s (%s)", metadata.Name, metadata.Serial)
		case metadata.Name != "":
			return metadata.Name
		case metadata.Serial != "":
			return metadata.Serial
		}
	}
	return peer.String()
}

func peerCountersLogString(peer *Peer) string {
	if peer == nil {
		return "txBytes=0 rxBytes=0 lastHandshake=<zero> handshakeAttempts=0 linkUp=false"
	}
	lastHandshake := "<zero>"
	if last := peer.lastHandshakeNano.Load(); last != 0 {
		lastHandshake = time.Unix(0, last).Format(time.RFC3339Nano)
	}
	return fmt.Sprintf(
		"txBytes=%d rxBytes=%d lastHandshake=%s handshakeAttempts=%d linkUp=%t",
		peer.txBytes.Load(),
		peer.rxBytes.Load(),
		lastHandshake,
		peer.timers.handshakeAttempts.Load(),
		peer.timers.linkUp.Load(),
	)
}

func logPeerDiagnosticEvery(peer *Peer, last *time.Time, template string, args ...any) {
	if peer == nil || peer.device == nil || last == nil {
		return
	}
	now := time.Now()
	peer.diagnostics.Lock()
	if !last.IsZero() && now.Sub(*last) < peerDiagnosticsLogInterval {
		peer.diagnostics.Unlock()
		return
	}
	*last = now
	peer.diagnostics.Unlock()
	peer.device.log.Verbosef(template, args...)
}

func packetKindCounts(bufs [][]byte) (data, keepalive, latencyProbe, latencyAck, peerClosing, other int) {
	for _, buf := range bufs {
		switch packetKind(buf) {
		case "data":
			data++
		case "keepalive":
			keepalive++
		case "latency-probe":
			latencyProbe++
		case "latency-ack":
			latencyAck++
		case "peer-closing":
			peerClosing++
		default:
			other++
		}
	}
	return
}

func packetKind(buf []byte) string {
	if len(buf) < 4 {
		return "short"
	}
	msgType := binary.LittleEndian.Uint32(buf[:4])
	switch msgType {
	case MessageTransportType:
		if len(buf) == MessageKeepaliveSize {
			return "keepalive"
		}
		return "data"
	case MessageLatencyProbeType:
		return "latency-probe"
	case MessageLatencyAckType:
		return "latency-ack"
	case MessagePeerClosingType:
		return "peer-closing"
	case MessageInitiationType:
		return "handshake-initiation"
	case MessageResponseType:
		return "handshake-response"
	default:
		return fmt.Sprintf("type-%d", msgType)
	}
}

func packetKindFromType(msgType uint32) string {
	switch msgType {
	case MessageTransportType:
		return "transport"
	case MessageLatencyProbeType:
		return "latency-probe"
	case MessageLatencyAckType:
		return "latency-ack"
	case MessagePeerClosingType:
		return "peer-closing"
	case MessageInitiationType:
		return "handshake-initiation"
	case MessageResponseType:
		return "handshake-response"
	default:
		return fmt.Sprintf("type-%d", msgType)
	}
}
