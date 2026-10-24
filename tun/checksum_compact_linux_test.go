/* SPDX-License-Identifier: MIT */

package tun

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// TestCompactFraming checks header size, byte-order setup and propagated errors.
func TestCompactFraming(t *testing.T) {
	t.Parallel()
	for _, size := range []int{0, 10, 12} {
		for _, failure := range []string{"", "get", "set"} {
			t.Run(fmt.Sprintf("%d/%s", size, failure), func(t *testing.T) {
				calls := 0
				err := configureCompactFraming(func() (int, error) {
					if failure == "get" {
						return 0, unix.EPERM
					}
					return size, nil
				}, func() error {
					calls++
					if failure == "set" {
						return unix.EPERM
					}
					return nil
				})
				valid := size == 10 && failure == ""
				if (err == nil) != valid {
					t.Fatal(err)
				}
				if calls != 0 && (size != 10 || failure == "get") {
					t.Fatal("configured invalid descriptor")
				}
				if (failure == "get" || size == 10 && failure == "set") && !errors.Is(err, unix.EPERM) {
					t.Fatal(err)
				}
			})
		}
	}
}

// partialChecksumPacket replaces a completed checksum with its pseudo-header sum.
func partialChecksumPacket(kind string, payload int) (wire, expected []byte) {
	var p []byte
	start, field, protocol := 20, 6, tcpip.TransportProtocolNumber(unix.IPPROTO_UDP)
	switch kind {
	case "tcp4":
		p = tcp4Packet(ip4PortA, ip4PortB, header.TCPFlagAck, uint32(payload), 123)
		field, protocol = 16, unix.IPPROTO_TCP
	case "tcp6":
		p = tcp6Packet(ip6PortA, ip6PortB, header.TCPFlagAck, uint32(payload), 123)
		start, field, protocol = 40, 16, unix.IPPROTO_TCP
	case "udp4":
		p = udp4Packet(ip4PortA, ip4PortB, payload)
	case "udp6":
		p = udp6Packet(ip6PortA, ip6PortB, payload)
		start = 40
	}
	expected = bytes.Clone(p[offset:])
	var pseudo uint16
	if start == 20 {
		ip := header.IPv4(expected)
		pseudo = header.PseudoHeaderChecksum(protocol, ip.SourceAddress(), ip.DestinationAddress(), uint16(len(expected)-start))
	} else {
		ip := header.IPv6(expected)
		pseudo = header.PseudoHeaderChecksum(protocol, ip.SourceAddress(), ip.DestinationAddress(), uint16(len(expected)-start))
	}
	wire = append(make([]byte, 10), expected...)
	wire[0] = unix.VIRTIO_NET_HDR_F_NEEDS_CSUM
	binary.LittleEndian.PutUint16(wire[6:8], uint16(start))
	binary.LittleEndian.PutUint16(wire[8:10], uint16(field))
	binary.BigEndian.PutUint16(wire[10+start+field:], pseudo)
	return
}

// TestCompactChecksum verifies complete packet bytes against independent fixtures.
func TestCompactChecksum(t *testing.T) {
	t.Parallel()
	for _, kind := range []string{"tcp4", "tcp6", "udp4", "udp6"} {
		for _, payload := range []int{0, 1, 37, 100, 1401} {
			t.Run(fmt.Sprintf("%s/%d", kind, payload), func(t *testing.T) {
				wire, want := partialChecksumPacket(kind, payload)
				before := bytes.Clone(wire)
				sizes := []int{-1}
				if _, err := readPlain(wire, true, make([]byte, len(want)-1), sizes, 0); !errors.Is(err, io.ErrShortBuffer) || !bytes.Equal(wire, before) || sizes[0] != -1 {
					t.Fatal("short output changed input", err)
				}
				out := make([]byte, len(want)+16)
				n, err := readPlain(wire, true, out, sizes, 16)
				if err != nil || n != 1 || sizes[0] != len(want) || !bytes.Equal(out[16:], want) {
					t.Fatalf("packet mismatch: %v", err)
				}
				wire[0] = unix.VIRTIO_NET_HDR_F_DATA_VALID
				if _, err := readPlain(wire, true, out, sizes, 16); err != nil || !bytes.Equal(out[16:], want) {
					t.Fatal("completed checksum changed", err)
				}
			})
		}
	}
}

// TestCompactChecksumBounds rejects invalid metadata before modifying packets.
func TestCompactChecksumBounds(t *testing.T) {
	t.Parallel()
	for _, pair := range [][2]uint16{{65535, 65535}, {65535, 1}, {40, 65535}, {90, 0}, {89, 0}, {0, 90}} {
		wire := make([]byte, 100)
		wire[0] = unix.VIRTIO_NET_HDR_F_NEEDS_CSUM
		binary.LittleEndian.PutUint16(wire[6:8], pair[0])
		binary.LittleEndian.PutUint16(wire[8:10], pair[1])
		before := bytes.Clone(wire)
		if _, err := readPlain(wire, true, make([]byte, 100), []int{0}, 0); err == nil || !bytes.Equal(wire, before) {
			t.Fatal(pair, err)
		}
	}
}

// BenchmarkCompactChecksum measures completion and copying without fixture allocation.
func BenchmarkCompactChecksum(b *testing.B) {
	wire, _ := partialChecksumPacket("udp6", 1401)
	seed := binary.BigEndian.Uint16(wire[56:58])
	out, sizes := make([]byte, 1600), []int{0}
	if _, err := readPlain(wire, true, out, sizes, 16); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		binary.BigEndian.PutUint16(wire[56:58], seed)
		if _, err := readPlain(wire, true, out, sizes, 16); err != nil {
			b.Fatal(err)
		}
	}
}

// TestCompactChecksumZero preserves a computed zero checksum as all ones.
// UDP uses a transmitted zero to mean that no checksum was supplied.
func TestCompactChecksumZero(t *testing.T) {
	t.Parallel()
	for _, kind := range []string{"udp4", "udp6"} {
		wire, _ := partialChecksumPacket(kind, 2)
		start := int(binary.LittleEndian.Uint16(wire[6:8]))
		field := int(binary.LittleEndian.Uint16(wire[8:10]))
		packet := wire[10:]
		// A single payload word can make the one's-complement checksum zero.
		for word := 0; word <= 65535; word++ {
			binary.BigEndian.PutUint16(packet[len(packet)-2:], uint16(word))
			if checksumRef(packet[start:], 0) == 0xffff {
				break
			}
		}
		out := make([]byte, len(packet))
		if _, err := readPlain(wire, true, out, []int{0}, 0); err != nil {
			t.Fatal(err)
		}
		if binary.BigEndian.Uint16(out[start+field:]) != 0xffff {
			t.Fatal("computed zero sent as missing UDP checksum")
		}
	}
}
