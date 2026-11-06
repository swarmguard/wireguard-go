/* SPDX-License-Identifier: MIT */

package device

import "fmt"

// packetBufferSize returns the fixed owned-buffer capacity for this device.
func (device *Device) packetBufferSize() int {
	if device.messageBufferSize == 0 {
		return MaxMessageSize
	}
	return device.messageBufferSize
}

// validatePacketBufferSize rejects unsafe limits before starting any workers.
func (device *Device) validatePacketBufferSize(mtu int) error {
	size := device.packetBufferSize()
	if size < MessageInitiationSize || size > MaxMessageSize {
		return fmt.Errorf("invalid WireGuard message buffer size: %d", size)
	}
	if device.packetBudget == nil || !device.packetBuffers.ReadConsumesWholePacket || !device.packetBuffers.WriteUsesPacketLength {
		return fmt.Errorf("small WireGuard buffers require a budget and packet-sized TUN I/O")
	}
	if mtu <= 0 || mtu > size-MessageTransportSize {
		return fmt.Errorf("MTU %d exceeds WireGuard message buffer payload capacity %d", mtu, size-MessageTransportSize)
	}
	return nil
}

// tunReadBuffer reserves the authentication tag when reads use small storage.
// The TUN consumes oversized packets atomically before returning an error.
func (device *Device) tunReadBuffer(buffer []byte) []byte {
	if device.packetBufferSize() < MaxMessageSize {
		return buffer[:len(buffer)-(MessageTransportSize-MessageTransportHeaderSize)]
	}
	return buffer
}
