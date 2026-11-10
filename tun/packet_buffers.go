/* SPDX-License-Identifier: MIT */

package tun

// PacketBufferCapabilities describes optional, lifetime-fixed guarantees for
// devices that can use packet-sized backing storage. Missing capabilities are
// conservative; batch size alone does not establish either guarantee.
type PacketBufferCapabilities struct {
	// ReadConsumesWholePacket means an oversized packet is consumed and returns
	// io.ErrShortBuffer, never a successful truncated packet. Valid packets in
	// a partial batch remain available to the caller before that error.
	ReadConsumesWholePacket bool

	// WriteUsesPacketLength means Write needs no capacity beyond each supplied
	// packet's length. It may modify packet contents and the reserved prefix
	// specified by offset, but does not retain buffers after returning,
	// including on errors.
	WriteUsesPacketLength bool

	// WriteMayGrowPacketStorage means packet-sized writes may allocate private
	// aggregation storage. Budget-managed callers must supply full buffers.
	WriteMayGrowPacketStorage bool
}

// PacketBuffers returns a device's explicitly advertised buffer guarantees.
func PacketBuffers(device Device) PacketBufferCapabilities {
	if provider, ok := device.(interface {
		PacketBufferCapabilities() PacketBufferCapabilities
	}); ok {
		return provider.PacketBufferCapabilities()
	}
	return PacketBufferCapabilities{}
}
