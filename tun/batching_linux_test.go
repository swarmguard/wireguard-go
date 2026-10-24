/* SPDX-License-Identifier: MIT */

package tun

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// batchAggregate builds a virtio aggregate with a short final segment.
func batchAggregate(kind string, segments int) []byte {
	payload := (segments-1)*100 + 37
	var packet []byte
	hdr := virtioNetHdr{flags: unix.VIRTIO_NET_HDR_F_NEEDS_CSUM, gsoSize: 100}
	switch kind {
	case "tcp4":
		packet = tcp4Packet(ip4PortA, ip4PortB, header.TCPFlagAck|header.TCPFlagPsh|header.TCPFlagFin, uint32(payload), 123)
		hdr.gsoType, hdr.csumStart, hdr.csumOffset = unix.VIRTIO_NET_HDR_GSO_TCPV4, 20, 16
	case "tcp6":
		packet = tcp6Packet(ip6PortA, ip6PortB, header.TCPFlagAck|header.TCPFlagPsh|header.TCPFlagFin, uint32(payload), 123)
		hdr.gsoType, hdr.csumStart, hdr.csumOffset = unix.VIRTIO_NET_HDR_GSO_TCPV6, 40, 16
	case "udp4":
		packet = udp4Packet(ip4PortA, ip4PortB, payload)
		hdr.gsoType, hdr.csumStart, hdr.csumOffset = unix.VIRTIO_NET_HDR_GSO_UDP_L4, 20, 6
	case "udp6":
		packet = udp6Packet(ip6PortA, ip6PortB, payload)
		hdr.gsoType, hdr.csumStart, hdr.csumOffset = unix.VIRTIO_NET_HDR_GSO_UDP_L4, 40, 6
	}
	// Distinct payload bytes expose loss, duplication and reordering between reads.
	transportLen := 8
	if kind[:3] == "tcp" {
		transportLen = 20
	}
	for i := offset + int(hdr.csumStart) + transportLen; i < len(packet); i++ {
		packet[i] = byte(i*37 + 11)
	}
	// Deliberately use a misleading hdrLen, as forwarding kernels can do.
	hdr.hdrLen = uint16(len(packet) - virtioNetHdrLen)
	_ = hdr.encode(packet)
	return packet
}

func batchBuffers(n int) ([][]byte, []int) {
	bufs := make([][]byte, n)
	for i := range bufs {
		bufs[i] = make([]byte, 2048)
	}
	return bufs, make([]int, n)
}

// TestNormalGSO checks payloads, headers and checksums for normal segmentation.
func TestNormalGSO(t *testing.T) {
	t.Parallel()
	for _, kind := range []string{"tcp4", "tcp6", "udp4", "udp6"} {
		for _, count := range []int{1, 7, 8, 9, 128, 129, 300} {
			t.Run(fmt.Sprintf("%s/%d", kind, count), func(t *testing.T) {
				original := batchAggregate(kind, count)
				bufs, sizes := batchBuffers(count)
				n, err := handleVirtioRead(bytes.Clone(original), bufs, sizes, 16)
				if n != count || err != nil {
					t.Fatal(n, err)
				}
				for i := 0; i < n; i++ {
					p := bufs[i][16 : 16+sizes[i]]
					ipLen, src, addrLen := 20, 12, 4
					if kind[3] == '6' {
						ipLen, src, addrLen = 40, 8, 16
						if int(binary.BigEndian.Uint16(p[4:])) != len(p)-40 {
							t.Fatal("IPv6 length")
						}
					} else if int(binary.BigEndian.Uint16(p[2:])) != len(p) || binary.BigEndian.Uint16(p[4:]) != uint16(i) || checksum(p[:20], 0) != 0xffff {
						t.Fatal("IPv4 header")
					}
					protocol, transportLen := uint8(unix.IPPROTO_UDP), 8
					if kind[:3] == "tcp" {
						protocol, transportLen = unix.IPPROTO_TCP, 20
						if binary.BigEndian.Uint32(p[ipLen+4:]) != uint32(123+100*i) {
							t.Fatal("TCP sequence")
						}
						flags := p[ipLen+13] & (tcpFlagFIN | tcpFlagPSH)
						if (i == count-1) != (flags == tcpFlagFIN|tcpFlagPSH) {
							t.Fatal("TCP final flags")
						}
					} else if int(binary.BigEndian.Uint16(p[ipLen+4:])) != len(p)-ipLen {
						t.Fatal("UDP length")
					}
					pseudo := pseudoHeaderChecksumNoFold(protocol, p[src:src+addrLen], p[src+addrLen:src+2*addrLen], uint16(len(p)-ipLen))
					if checksum(p[ipLen:], pseudo) != 0xffff {
						t.Fatal("transport checksum")
					}
					start := offset + ipLen + transportLen + i*100
					if !bytes.Equal(p[ipLen+transportLen:], original[start:start+len(p)-ipLen-transportLen]) {
						t.Fatal("payload order")
					}
				}
			})
		}
	}
}

// socketTun exercises native I/O without privileged kernel setup.
func socketTun(t testing.TB, disabled, framed bool) (*NativeTun, *os.File) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	dev := &NativeTun{tunFile: os.NewFile(uintptr(fds[0]), "tun-test"), events: make(chan Event), errors: make(chan error)}
	flags := uint16(0)
	if framed {
		flags = unix.IFF_VNET_HDR
	}
	if err := dev.configureOffloads(flags, Options{DisableOffloads: disabled}, func(int) error { return nil }); err != nil {
		t.Fatal(err)
	}
	peer := os.NewFile(uintptr(fds[1]), "tun-peer")
	t.Cleanup(func() { _ = dev.Close(); _ = peer.Close() })
	return dev, peer
}

// TestOffloadOptions verifies normal negotiation and compact allocation avoidance.
func TestOffloadOptions(t *testing.T) {
	t.Parallel()
	for _, framed := range []bool{false, true} {
		for _, disabled := range []bool{false, true} {
			for _, fail := range []int{-1, 0, 1} {
				var dev NativeTun
				var calls []int
				flags := uint16(0)
				if framed {
					flags = unix.IFF_VNET_HDR
				}
				err := dev.configureOffloads(flags, Options{DisableOffloads: disabled}, func(v int) error {
					calls = append(calls, v)
					if len(calls)-1 == fail {
						return unix.EPERM
					}
					return nil
				})
				if dev.disableOffloads != disabled || dev.vnetHdr != framed {
					t.Fatal("settings/framing changed")
				}
				if framed && fail == 0 {
					if !errors.Is(err, unix.EPERM) {
						t.Fatal("setup did not fail", err)
					}
					if disabled && (dev.tcpGROTable != nil || dev.udpGROTable != nil || dev.toWrite != nil) {
						t.Fatal("compact failure allocated GRO state")
					}
					continue
				}
				if err != nil {
					t.Fatal(err)
				}
				if disabled {
					if dev.BatchSize() != 1 || dev.udpGSO || dev.tcpGROTable != nil || dev.udpGROTable != nil || dev.toWrite != nil {
						t.Fatal("compact setup allocated offload state")
					}
					if framed && (len(calls) != 1 || calls[0] != 0) {
						t.Fatal("offloads not cleared")
					}
				} else {
					if dev.tcpGROTable == nil || dev.udpGROTable == nil || cap(dev.toWrite) != 128 {
						t.Fatal("normal allocations changed")
					}
					if framed {
						if dev.BatchSize() != 128 || len(calls) != 2 || calls[0] != tunTCPOffloads || calls[1] != tunTCPOffloads|tunUDPOffloads || dev.udpGSO != (fail != 1) {
							t.Fatal("normal negotiation changed")
						}
					} else if dev.BatchSize() != 1 || dev.udpGSO {
						t.Fatal("normal plain descriptor changed")
					}
				}
				if !framed && len(calls) != 0 {
					t.Fatal("ioctl for plain descriptor")
				}
			}
		}
	}
}

// TestCompactReadWrite checks packet integrity with and without virtio framing.
func TestCompactReadWrite(t *testing.T) {
	t.Parallel()
	for _, framed := range []bool{false, true} {
		t.Run(fmt.Sprint(framed), func(t *testing.T) {
			dev, peer := socketTun(t, true, framed)
			packets := [][]byte{}
			for _, kind := range []string{"tcp4", "tcp6", "udp4", "udp6"} {
				bufs, sizes := batchBuffers(33)
				if _, err := handleVirtioRead(batchAggregate(kind, 33), bufs, sizes, 16); err != nil {
					t.Fatal(err)
				}
				for i := range bufs {
					packets = append(packets, bufs[i][:16+sizes[i]])
				}
			}
			bufs, sizes := batchBuffers(128)
			for _, p := range packets {
				wire := p[16:]
				if framed {
					wire = append(make([]byte, virtioNetHdrLen), wire...)
				}
				if _, err := peer.Write(wire); err != nil {
					t.Fatal(err)
				}
				if n, err := dev.Read(bufs, sizes, 16); n != 1 || err != nil {
					t.Fatal(n, err)
				}
				if !bytes.Equal(p[16:], bufs[0][16:16+sizes[0]]) {
					t.Fatal("read changed packet")
				}
			}
			done := make(chan error, 1)
			go func() {
				b := make([]byte, 65545)
				for _, p := range packets {
					n, err := peer.Read(b)
					if err != nil {
						done <- err
						return
					}
					start := 0
					if framed {
						start = virtioNetHdrLen
						if !bytes.Equal(b[:start], make([]byte, start)) {
							done <- errors.New("nonzero virtio header")
							return
						}
					}
					if !bytes.Equal(b[start:n], p[16:]) {
						done <- errors.New("write order/bytes")
						return
					}
				}
				done <- nil
			}()
			want := 0
			for _, p := range packets {
				want += len(p) - 16
				if framed {
					want += virtioNetHdrLen
				}
			}
			// More than 128 packets also works without any GRO table capacity.
			if n, err := dev.Write(packets, 16); n != want || err != nil {
				t.Fatal(n, want, err)
			}
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("write blocked")
			}
		})
	}
}

// TestCompactInvalidRead rejects offload requests and silent truncation.
func TestCompactInvalidRead(t *testing.T) {
	t.Parallel()
	for _, framed := range []bool{false, true} {
		dev, peer := socketTun(t, true, framed)
		bufs, sizes := batchBuffers(8)
		for _, off := range []int{-1, 2049} {
			if _, err := dev.Read(bufs, sizes, off); err == nil {
				t.Fatal("invalid offset")
			}
		}
		if _, err := dev.Read(nil, sizes, 16); err == nil {
			t.Fatal("empty buffers")
		}
		if _, err := dev.Read(bufs, nil, 16); err == nil {
			t.Fatal("empty sizes")
		}
		packet := udp4Packet(ip4PortA, ip4PortB, 37)
		clear(packet[:offset])
		wire := packet
		if !framed {
			wire = packet[offset:]
		}
		_, _ = peer.Write(wire)
		if _, err := dev.Read([][]byte{make([]byte, 20)}, sizes, 16); !errors.Is(err, io.ErrShortBuffer) {
			t.Fatal(err)
		}
		if _, err := dev.Write(bufs, -1); !errors.Is(err, io.ErrShortBuffer) {
			t.Fatal(err)
		}
		if framed {
			for _, p := range [][]byte{{}, {0}, make([]byte, virtioNetHdrLen), batchAggregate("tcp4", 9)} {
				_, _ = peer.Write(p)
				if _, err := dev.Read(bufs, sizes, 16); err == nil {
					t.Fatal("invalid virtio accepted")
				}
			}
			h := virtioNetHdr{flags: unix.VIRTIO_NET_HDR_F_NEEDS_CSUM}
			_ = h.encode(packet)
			_, _ = peer.Write(packet)
			if _, err := dev.Read(bufs, sizes, 16); err == nil {
				t.Fatal("partial checksum accepted")
			}
			if _, err := dev.Write(bufs, 0); !errors.Is(err, io.ErrShortBuffer) {
				t.Fatal(err)
			}
		}
	}
}

// TestNativeReadClose verifies both modes stop reads and writes after closure.
func TestNativeReadClose(t *testing.T) {
	t.Parallel()
	for _, disabled := range []bool{false, true} {
		dev, _ := socketTun(t, disabled, true)
		bufs, sizes := batchBuffers(128)
		done := make(chan error, 1)
		go func() { _, err := dev.Read(bufs, sizes, 16); done <- err }()
		_ = dev.Close()
		_ = dev.Close()
		select {
		case err := <-done:
			if !errors.Is(err, os.ErrClosed) {
				t.Fatal(err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("read did not unblock")
		}
		if _, err := dev.Read(bufs, sizes, 16); !errors.Is(err, os.ErrClosed) {
			t.Fatal(err)
		}
		packet := udp4Packet(ip4PortA, ip4PortB, 37)
		if _, err := dev.Write([][]byte{packet}, offset); !errors.Is(err, os.ErrClosed) {
			t.Fatal(err)
		}
	}
}

// FuzzCompactRead checks compact framing and output bounds without exercising
// the normal-mode GSO parser, whose validation is outside this change.
func FuzzCompactRead(f *testing.F) {
	for _, kind := range []string{"tcp4", "tcp6", "udp4", "udp6"} {
		f.Add(batchAggregate(kind, 9))
	}
	f.Add([]byte{})
	plain := udp4Packet(ip4PortA, ip4PortB, 37)
	clear(plain[:offset])
	f.Add(plain)
	f.Fuzz(func(t *testing.T, p []byte) {
		if len(p) > 65545 {
			return
		}
		bufs, sizes := batchBuffers(128)
		_, _ = readPlain(p, true, bufs[0], sizes, 16)
		_, _ = readPlain(p, false, bufs[0], sizes, 16)
	})
}

// TestNativePlainRead checks no-GSO checksum completion and the one-packet
// backend without changing packet capacities or consuming invalid output.
func TestNativePlainRead(t *testing.T) {
	t.Parallel()
	dev, writer := socketTun(t, false, true)
	packet := udp4Packet(ip4PortA, ip4PortB, 37)
	expected := bytes.Clone(packet[offset:])
	pseudo := header.PseudoHeaderChecksum(unix.IPPROTO_UDP, header.IPv4(expected).SourceAddress(), header.IPv4(expected).DestinationAddress(), uint16(len(expected)-20))
	binary.BigEndian.PutUint16(packet[offset+26:], pseudo)
	hdr := virtioNetHdr{flags: unix.VIRTIO_NET_HDR_F_NEEDS_CSUM, csumStart: 20, csumOffset: 6}
	_ = hdr.encode(packet)
	_, _ = writer.Write(packet)
	bufs, sizes := batchBuffers(8)
	if n, err := dev.Read(bufs, sizes, 16); n != 1 || err != nil {
		t.Fatal(n, err)
	}
	if !bytes.Equal(bufs[0][16:16+sizes[0]], expected) {
		t.Fatal("partial checksum differs")
	}
	plain, plainWriter := socketTun(t, true, false)
	plain.vnetHdr = false
	_, _ = plainWriter.Write(expected)
	if n, err := plain.Read(bufs, sizes, 16); n != 1 || err != nil {
		t.Fatal(n, err)
	}
	if !bytes.Equal(bufs[0][16:16+sizes[0]], expected) {
		t.Fatal("plain packet differs")
	}
}
