// SPDX-License-Identifier: MIT

package packetbudget

import "encoding/binary"

// ControlSlots keeps shared queues available to control traffic during data
// saturation. It does not protect against an unlimited control flood.
const ControlSlots = 8

// IsControl recognizes exact WireGuard wire formats for reserve admission.
// It makes no authentication claim; normal crypto and replay checks still run.
func IsControl(packet []byte) bool {
	if len(packet) < 4 {
		return false
	}
	switch binary.LittleEndian.Uint32(packet[:4]) {
	case 1:
		return len(packet) == 148
	case 2:
		return len(packet) == 92
	case 3:
		return len(packet) == 64
	case 4, 5:
		return len(packet) == 32
	case 6, 7:
		return len(packet) == 40
	default:
		return false
	}
}
