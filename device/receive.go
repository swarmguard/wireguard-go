/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.zx2c4.com/wireguard/conn"
)

type QueueHandshakeElement struct {
	msgType        uint32
	packet         []byte
	endpoint       conn.Endpoint
	buffer         *[MaxMessageSize]byte
	borrowedPacket conn.BorrowedPacket
}

type QueueInboundElement struct {
	buffer         *[MaxMessageSize]byte
	packet         []byte
	counter        uint64
	keypair        *Keypair
	endpoint       conn.Endpoint
	borrowedPacket conn.BorrowedPacket
	msgType        uint32
}

type QueueInboundElementsContainer struct {
	sync.Mutex
	elems []*QueueInboundElement
}

// clearPointers clears elem fields that contain pointers.
// This makes the garbage collector's life easier and
// avoids accidentally keeping other objects around unnecessarily.
// It also reduces the possible collateral damage from use-after-free bugs.
func (elem *QueueInboundElement) clearPointers() {
	elem.buffer = nil
	elem.packet = nil
	elem.keypair = nil
	elem.endpoint = nil
	elem.borrowedPacket = nil
	elem.msgType = 0
}

func (elem *QueueHandshakeElement) releasePacket(device *Device) {
	if elem.borrowedPacket != nil {
		elem.borrowedPacket.Release()
		elem.borrowedPacket = nil
	} else if elem.buffer != nil {
		device.PutMessageBuffer(elem.buffer)
		elem.buffer = nil
	}
	elem.packet = nil
	elem.endpoint = nil
}

func (elem *QueueInboundElement) releasePacket(device *Device) {
	if elem.borrowedPacket != nil {
		elem.borrowedPacket.Release()
		elem.borrowedPacket = nil
	} else if elem.buffer != nil {
		device.PutMessageBuffer(elem.buffer)
		elem.buffer = nil
	}
	elem.packet = nil
}

func (elem *QueueInboundElement) backingBuffer() []byte {
	if elem.buffer != nil {
		return elem.buffer[:]
	}
	if elem.borrowedPacket != nil {
		return elem.borrowedPacket.Bytes()
	}
	return nil
}

/* Called when a new authenticated message has been received
 *
 * NOTE: Not thread safe, but called by sequential receiver!
 */
func (peer *Peer) keepKeyFreshReceiving() {
	if peer.timers.sentLastMinuteHandshake.Load() {
		return
	}
	keypair := peer.keypairs.Current()
	if keypair != nil && keypair.isInitiator && time.Since(keypair.created) > (RejectAfterTime-KeepaliveTimeout-RekeyTimeout) {
		peer.timers.sentLastMinuteHandshake.Store(true)
		peer.SendHandshakeInitiation(false)
	}
}

func (device *Device) RoutineReceiveIncomingBorrowed(maxBatchSize int, recv conn.ReceiveBorrowedFunc) {
	recvName := recv.PrettyName()
	defer func() {
		device.log.Verbosef("Routine: receive incoming %s - stopped", recvName)
		device.queue.decryption.wg.Done()
		device.queue.handshake.wg.Done()
		device.net.stopping.Done()
	}()

	device.log.Verbosef("Routine: receive incoming %s - started", recvName)

	var (
		packets     = make([]conn.BorrowedPacket, maxBatchSize)
		err         error
		count       int
		deathSpiral int
		elemsByPeer = make(map[*Peer]*QueueInboundElementsContainer, maxBatchSize)
	)

	for {
		count, err = recv(packets)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			device.log.Verbosef("Failed to receive %s packet: %v", recvName, err)
			if neterr, ok := err.(net.Error); ok && !neterr.Temporary() {
				return
			}
			if deathSpiral < 10 {
				deathSpiral++
				time.Sleep(time.Second / 3)
				continue
			}
			return
		}
		deathSpiral = 0

		for i := 0; i < count; i++ {
			borrowedPacket := packets[i]
			if borrowedPacket == nil {
				continue
			}
			packet := borrowedPacket.Bytes()
			if len(packet) < MinMessageSize {
				borrowedPacket.Release()
				packets[i] = nil
				continue
			}

			msgType := binary.LittleEndian.Uint32(packet[:4])

			switch msgType {

			// check if transport

			case MessageTransportType, MessagePeerClosingType, MessageLatencyProbeType, MessageLatencyAckType:

				// check size

				switch msgType {
				case MessageTransportType, MessagePeerClosingType:
					if len(packet) < MessageTransportSize {
						borrowedPacket.Release()
						packets[i] = nil
						continue
					}
				case MessageLatencyProbeType:
					if len(packet) != MessageLatencyProbeSize {
						borrowedPacket.Release()
						packets[i] = nil
						continue
					}
				case MessageLatencyAckType:
					if len(packet) != MessageLatencyAckSize {
						borrowedPacket.Release()
						packets[i] = nil
						continue
					}
				}

				receiver := binary.LittleEndian.Uint32(
					packet[MessageTransportOffsetReceiver:MessageTransportOffsetCounter],
				)
				value := device.indexTable.Lookup(receiver)
				keypair := value.keypair
				if keypair == nil {
					borrowedPacket.Release()
					packets[i] = nil
					continue
				}

				if keypair.created.Add(RejectAfterTime).Before(time.Now()) {
					borrowedPacket.Release()
					packets[i] = nil
					continue
				}

				peer := value.peer
				elem := device.GetInboundElement()
				elem.packet = packet
				elem.borrowedPacket = borrowedPacket
				elem.keypair = keypair
				elem.endpoint = borrowedPacket.Endpoint()
				elem.counter = 0
				elem.msgType = msgType

				elemsForPeer, ok := elemsByPeer[peer]
				if !ok {
					elemsForPeer = device.GetInboundElementsContainer()
					elemsForPeer.Lock()
					elemsByPeer[peer] = elemsForPeer
				}
				elemsForPeer.elems = append(elemsForPeer.elems, elem)
				packets[i] = nil
				continue

			case MessageInitiationType:
				if len(packet) != MessageInitiationSize {
					borrowedPacket.Release()
					packets[i] = nil
					continue
				}
			case MessageResponseType:
				if len(packet) != MessageResponseSize {
					borrowedPacket.Release()
					packets[i] = nil
					continue
				}
			case MessageCookieReplyType:
				if len(packet) != MessageCookieReplySize {
					borrowedPacket.Release()
					packets[i] = nil
					continue
				}
			default:
				device.log.Verbosef("Received message with unknown type")
				borrowedPacket.Release()
				packets[i] = nil
				continue
			}

			handshakeElem := QueueHandshakeElement{
				msgType:        msgType,
				packet:         packet,
				endpoint:       borrowedPacket.Endpoint(),
				borrowedPacket: borrowedPacket,
			}
			select {
			case device.queue.handshake.c <- handshakeElem:
				packets[i] = nil
			default:
				borrowedPacket.Release()
				packets[i] = nil
			}
		}
		for peer, elemsContainer := range elemsByPeer {
			if peer.isRunning.Load() {
				peer.queue.inbound.c <- elemsContainer
				device.queue.decryption.c <- elemsContainer
			} else {
				for _, elem := range elemsContainer.elems {
					elem.releasePacket(device)
					device.PutInboundElement(elem)
				}
				device.PutInboundElementsContainer(elemsContainer)
			}
			delete(elemsByPeer, peer)
		}
	}
}

func (device *Device) RoutineDecryption(id int) {
	var nonce [chacha20poly1305.NonceSize]byte

	defer device.log.Verbosef("Routine: decryption worker %d - stopped", id)
	device.log.Verbosef("Routine: decryption worker %d - started", id)

	for elemsContainer := range device.queue.decryption.c {
		for _, elem := range elemsContainer.elems {
			// split message into fields
			counter := elem.packet[MessageTransportOffsetCounter:MessageTransportOffsetContent]
			content := elem.packet[MessageTransportOffsetContent:]

			// decrypt and release to consumer
			var err error
			elem.counter = binary.LittleEndian.Uint64(counter)
			// copy counter to nonce
			binary.LittleEndian.PutUint64(nonce[0x4:0xc], elem.counter)
			elem.packet, err = elem.keypair.receive.Open(
				content[:0],
				nonce[:],
				content,
				nil,
			)
			if err != nil {
				elem.packet = nil
			}
		}
		elemsContainer.Unlock()
	}
}

/* Handles incoming packets related to handshake
 */
func (device *Device) RoutineHandshake(id int) {
	defer func() {
		device.log.Verbosef("Routine: handshake worker %d - stopped", id)
		device.queue.encryption.wg.Done()
	}()
	device.log.Verbosef("Routine: handshake worker %d - started", id)

	for elem := range device.queue.handshake.c {

		// handle cookie fields and ratelimiting

		switch elem.msgType {

		case MessageCookieReplyType:

			// unmarshal packet

			var reply MessageCookieReply
			err := reply.unmarshal(elem.packet)
			if err != nil {
				device.log.Verbosef("Failed to decode cookie reply")
				goto skip
			}

			// lookup peer from index

			entry := device.indexTable.Lookup(reply.Receiver)

			if entry.peer == nil {
				goto skip
			}

			// consume reply

			if peer := entry.peer; peer.isRunning.Load() {
				device.log.Verbosef("Receiving cookie response from %s", elem.endpoint.DstToString())
				if !peer.cookieGenerator.ConsumeReply(&reply) {
					device.log.Verbosef("Could not decrypt invalid cookie response")
				}
			}

			goto skip

		case MessageInitiationType, MessageResponseType:

			// check mac fields and maybe ratelimit

			if !device.cookieChecker.CheckMAC1(elem.packet) {
				device.log.Verbosef("Received packet with invalid mac1")
				goto skip
			}

			// endpoints destination address is the source of the datagram

			if device.IsUnderLoad() {

				// verify MAC2 field

				if !device.cookieChecker.CheckMAC2(elem.packet, elem.endpoint.DstToBytes()) {
					device.SendHandshakeCookie(&elem)
					goto skip
				}

				// check ratelimiter

				if !device.rate.limiter.Allow(elem.endpoint.DstIP()) {
					goto skip
				}
			}

		default:
			device.log.Errorf("Invalid packet ended up in the handshake queue")
			goto skip
		}

		// handle handshake initiation/response content

		switch elem.msgType {
		case MessageInitiationType:

			// unmarshal

			var msg MessageInitiation
			err := msg.unmarshal(elem.packet)
			if err != nil {
				device.log.Errorf("Failed to decode initiation message")
				goto skip
			}

			// consume initiation

			peer := device.ConsumeMessageInitiation(&msg)
			if peer == nil {
				device.log.Verbosef("Received invalid initiation message from %s", elem.endpoint.DstToString())
				goto skip
			}

			// update timers

			peer.timersAnyAuthenticatedPacketTraversal()
			peer.timersAnyAuthenticatedPacketReceived()
			peer.kickLinkWatchdog()

			// update endpoint
			peer.SetEndpointFromPacket(elem.endpoint)

			device.log.Verbosef("%s - Received handshake initiation; %s", peerLogLabel(peer), peerCountersLogString(peer))
			peer.rxBytes.Add(uint64(len(elem.packet)))

			peer.SendHandshakeResponse()

		case MessageResponseType:

			// unmarshal

			var msg MessageResponse
			err := msg.unmarshal(elem.packet)
			if err != nil {
				device.log.Errorf("Failed to decode response message")
				goto skip
			}

			// consume response

			peer := device.ConsumeMessageResponse(&msg)
			if peer == nil {
				device.log.Verbosef("Received invalid response message from %s", elem.endpoint.DstToString())
				goto skip
			}

			// update endpoint
			peer.SetEndpointFromPacket(elem.endpoint)

			device.log.Verbosef("%s - Received handshake response; %s", peerLogLabel(peer), peerCountersLogString(peer))
			peer.rxBytes.Add(uint64(len(elem.packet)))

			// update timers

			peer.timersAnyAuthenticatedPacketTraversal()
			peer.timersAnyAuthenticatedPacketReceived()
			peer.kickLinkWatchdog()

			// derive keypair

			err = peer.BeginSymmetricSession()

			if err != nil {
				device.log.Errorf("%v - Failed to derive keypair: %v", peer, err)
				goto skip
			}

			peer.timersSessionDerived()
			peer.timersHandshakeComplete()
			peer.SendKeepalive()
		}
	skip:
		elem.releasePacket(device)
	}
}

func (peer *Peer) RoutineSequentialReceiver(maxBatchSize int) {
	device := peer.device
	defer func() {
		device.log.Verbosef("%v - Routine: sequential receiver - stopped", peer)
		peer.stopping.Done()
	}()
	device.log.Verbosef("%v - Routine: sequential receiver - started", peer)

	bufs := make([][]byte, 0, maxBatchSize)

	for elemsContainer := range peer.queue.inbound.c {
		if elemsContainer == nil {
			return
		}
		elemsContainer.Lock()
		validTailPacket := -1
		dataPacketReceived := false
		decryptFailures := 0
		replayRejects := 0
		keepalives := 0
		latencyProbes := 0
		latencyAcks := 0
		peerClosings := 0
		dataPackets := 0
		rxBytesLen := uint64(0)
		for i, elem := range elemsContainer.elems {
			if elem.packet == nil {
				// decryption failed
				decryptFailures++
				logPeerDiagnosticEvery(peer, &peer.diagnostics.lastDecryptFailureAt, "%s - Rejected inbound transport packet: decrypt failed; %s", peerLogLabel(peer), peerCountersLogString(peer))
				continue
			}

			if !elem.keypair.replayFilter.ValidateCounter(elem.counter, RejectAfterMessages) {
				replayRejects++
				logPeerDiagnosticEvery(peer, &peer.diagnostics.lastReplayRejectAt, "%s - Rejected inbound transport packet: replay counter=%d; %s", peerLogLabel(peer), elem.counter, peerCountersLogString(peer))
				continue
			}

			if peer.ReceivedWithKeypair(elem.keypair) {
				peer.SetEndpointFromPacket(elem.endpoint)
				peer.timersHandshakeComplete()
				peer.SendStagedPackets()
			}
			rxBytesLen += uint64(len(elem.packet) + MinMessageSize)

			if elem.msgType == MessagePeerClosingType {
				peerClosings++
				device.log.Verbosef("%s - Received peer-closing notice", peerLogLabel(peer))
				peer.notePeerClosing()
				continue
			}

			if elem.msgType == MessageLatencyProbeType || elem.msgType == MessageLatencyAckType {
				token, ok := decodeLatencyToken(elem.packet)
				if !ok {
					continue
				}

				validTailPacket = i
				peer.kickLinkWatchdog()
				switch elem.msgType {
				case MessageLatencyProbeType:
					latencyProbes++
					device.log.Verbosef("%s - Received latency probe", peerLogLabel(peer))
					peer.handleLatencyProbe(token)
				case MessageLatencyAckType:
					latencyAcks++
					device.log.Verbosef("%s - Received latency probe ack", peerLogLabel(peer))
					peer.handleLatencyAck(token)
				}
				continue
			}

			validTailPacket = i
			if len(elem.packet) == 0 {
				keepalives++
				device.log.Verbosef("%s - Receiving keepalive packet", peerLogLabel(peer))
				peer.kickLinkWatchdog()
				continue
			}
			dataPacketReceived = true
			dataPackets++

			switch elem.packet[0] >> 4 {
			case 4:
				if len(elem.packet) < ipv4.HeaderLen {
					continue
				}
				field := elem.packet[IPv4offsetTotalLength : IPv4offsetTotalLength+2]
				length := binary.BigEndian.Uint16(field)
				if int(length) > len(elem.packet) || int(length) < ipv4.HeaderLen {
					continue
				}
				elem.packet = elem.packet[:length]
				src := elem.packet[IPv4offsetSrc : IPv4offsetSrc+net.IPv4len]
				if device.allowedips.Lookup(src) != peer {
					logPeerDiagnosticEvery(peer, &peer.diagnostics.lastDisallowedSourceAt, "%s - Rejected inbound IPv4 packet: disallowed source address; %s", peerLogLabel(peer), peerCountersLogString(peer))
					continue
				}

			case 6:
				if len(elem.packet) < ipv6.HeaderLen {
					continue
				}
				field := elem.packet[IPv6offsetPayloadLength : IPv6offsetPayloadLength+2]
				length := binary.BigEndian.Uint16(field)
				length += ipv6.HeaderLen
				if int(length) > len(elem.packet) {
					continue
				}
				elem.packet = elem.packet[:length]
				src := elem.packet[IPv6offsetSrc : IPv6offsetSrc+net.IPv6len]
				if device.allowedips.Lookup(src) != peer {
					logPeerDiagnosticEvery(peer, &peer.diagnostics.lastDisallowedSourceAt, "%s - Rejected inbound IPv6 packet: disallowed source address; %s", peerLogLabel(peer), peerCountersLogString(peer))
					continue
				}

			default:
				logPeerDiagnosticEvery(peer, &peer.diagnostics.lastInvalidIPVersionAt, "%s - Rejected inbound transport packet: invalid IP version; %s", peerLogLabel(peer), peerCountersLogString(peer))
				continue
			}

			backingBuffer := elem.backingBuffer()
			if backingBuffer == nil {
				continue
			}
			bufs = append(bufs, backingBuffer[:MessageTransportOffsetContent+len(elem.packet)])
		}

		peer.rxBytes.Add(rxBytesLen)
		if validTailPacket >= 0 {
			peer.SetEndpointFromPacket(elemsContainer.elems[validTailPacket].endpoint)
			peer.keepKeyFreshReceiving()
			peer.timersAnyAuthenticatedPacketTraversal()
			peer.timersAnyAuthenticatedPacketReceived()
		}
		if dataPacketReceived {
			peer.timersDataReceived()
		}
		if decryptFailures > 0 || replayRejects > 0 || keepalives > 0 || latencyProbes > 0 || latencyAcks > 0 || peerClosings > 0 || dataPackets > 0 {
			device.log.Verbosef(
				"%s - Inbound WireGuard transport batch: data=%d keepalive=%d latencyProbe=%d latencyAck=%d peerClosing=%d decryptFailed=%d replayRejected=%d rxBytes=%d; %s",
				peerLogLabel(peer),
				dataPackets,
				keepalives,
				latencyProbes,
				latencyAcks,
				peerClosings,
				decryptFailures,
				replayRejects,
				rxBytesLen,
				peerCountersLogString(peer),
			)
		}
		if len(bufs) > 0 {
			_, err := device.tun.device.Write(bufs, MessageTransportOffsetContent)
			if err != nil && !device.isClosed() {
				device.log.Errorf("Failed to write packets to TUN device: %v", err)
			}
		}
		for _, elem := range elemsContainer.elems {
			elem.releasePacket(device)
			device.PutInboundElement(elem)
		}
		bufs = bufs[:0]
		device.PutInboundElementsContainer(elemsContainer)
	}
}
