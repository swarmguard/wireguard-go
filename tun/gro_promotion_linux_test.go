//go:build linux

/* SPDX-License-Identifier: MIT */

package tun

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// TestGROPromotionMatchesLargeBuffers preserves TCP/UDP output for both IP
// families, including prepend, short tails, PSH, and invalid checksums.
func TestGROPromotionMatchesLargeBuffers(t *testing.T) {
	t.Parallel()
	tcp4 := func(seq uint32) []byte { return tcp4Packet(ip4PortA, ip4PortB, header.TCPFlagAck, 100, seq) }
	tcp6 := func(seq uint32) []byte { return tcp6Packet(ip6PortA, ip6PortB, header.TCPFlagAck, 100, seq) }
	invalid := tcp4(101)
	invalid[len(invalid)-1] ^= 1
	cases := []struct {
		name    string
		packets [][]byte
	}{
		{"tcp4-append", [][]byte{tcp4(1), tcp4(101), tcp4(201)}},
		{"tcp4-prepend", [][]byte{tcp4(201), tcp4(101), tcp4(1)}},
		{"tcp6-append", [][]byte{tcp6(1), tcp6(101), tcp6(201)}},
		{"tcp6-prepend", [][]byte{tcp6(201), tcp6(101), tcp6(1)}},
		{"tcp4-short", [][]byte{tcp4(1), tcp4Packet(ip4PortA, ip4PortB, header.TCPFlagAck|header.TCPFlagPsh, 40, 101)}},
		{"udp4", [][]byte{udp4Packet(ip4PortA, ip4PortB, 100), udp4Packet(ip4PortA, ip4PortB, 100)}},
		{"udp6", [][]byte{udp6Packet(ip6PortA, ip6PortB, 100), udp6Packet(ip6PortA, ip6PortB, 100)}},
		{"bad-checksum", [][]byte{tcp4(1), invalid, tcp4(201)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			run := func(lazy bool) [][]byte {
				bufs := make([][]byte, len(tc.packets))
				original := make([][]byte, len(bufs))
				for i, p := range tc.packets {
					capacity := 65535
					if lazy {
						capacity = len(p)
					}
					bufs[i] = make([]byte, len(p), capacity)
					copy(bufs[i], p)
					original[i] = bufs[i]
				}
				tcp, udp := newTCPGROTable(), newUDPGROTable()
				var promotion groPromotion
				if lazy {
					promotion.begin(bufs)
					tcp.promotion = &promotion
					udp.promotion = &promotion
				}
				var writes []int
				if err := handleGRO(bufs, offset, tcp, udp, true, &writes); err != nil {
					t.Fatal(err)
				}
				result := make([][]byte, len(writes))
				for i, j := range writes {
					result[i] = bytes.Clone(bufs[j])
				}
				if lazy {
					promotion.finish(bufs)
					for i := range bufs {
						if &bufs[i][0] != &original[i][0] || len(bufs[i]) != len(original[i]) || cap(bufs[i]) != cap(original[i]) {
							t.Fatal("caller slice header changed")
						}
					}
					for _, v := range promotion.originals {
						if v != nil {
							t.Fatal("borrowed reference retained")
						}
					}
				}
				return result
			}
			want, got := run(false), run(true)
			if len(want) != len(got) {
				t.Fatalf("writes %d != %d", len(got), len(want))
			}
			for i := range want {
				if !bytes.Equal(want[i], got[i]) {
					t.Fatalf("output %d differs", i)
				}
			}
		})
	}
}

// TestGROPromotionBound supports a full mixed-flow batch within bounded storage.
func TestGROPromotionBound(t *testing.T) {
	t.Parallel()
	var bufs [][]byte
	for i := 0; i < 64; i++ {
		src := netip.AddrPortFrom(ip4PortA.Addr(), uint16(1000+i))
		for j := 0; j < 2; j++ {
			p := tcp4Packet(src, ip4PortB, header.TCPFlagAck, 100, uint32(1+j*100))
			bufs = append(bufs, bytes.Clone(p))
		}
	}
	var promotion groPromotion
	promotion.begin(bufs)
	tcp, udp := newTCPGROTable(), newUDPGROTable()
	tcp.promotion = &promotion
	udp.promotion = &promotion
	var writes []int
	if err := handleGRO(bufs, offset, tcp, udp, true, &writes); err != nil {
		t.Fatal(err)
	}
	if promotion.used != 64 || len(writes) != 64 {
		t.Fatalf("used=%d writes=%d", promotion.used, len(writes))
	}
	total := 0
	for _, i := range writes {
		total += len(bufs[i]) - offset - 40
	}
	if total != 12800 {
		t.Fatalf("payload conservation: %d", total)
	}
	promotion.finish(bufs)
	for _, buffer := range promotion.buffers {
		if buffer != nil && len(buffer) != 65536 {
			t.Fatal("unbounded buffer")
		}
	}
}

// BenchmarkGROPromotion includes the eager receive copy in the control and
// on-demand head growth in the candidate, with reusable storage in both cases.
func BenchmarkGROPromotion(b *testing.B) {
	for _, flows := range []int{1, 16, 32} {
		for _, lazy := range []bool{false, true} {
			b.Run(fmt.Sprintf("flows-%d/lazy-%t", flows, lazy), func(b *testing.B) {
				const count = 64
				raw := make([][]byte, count)
				small := make([][]byte, count)
				large := make([][]byte, count)
				bufs := make([][]byte, count)
				for i := range raw {
					src := netip.AddrPortFrom(ip4PortA.Addr(), uint16(1000+i%flows))
					raw[i] = bytes.Clone(tcp4Packet(src, ip4PortB, header.TCPFlagAck, 1200, uint32(1+(i/flows)*1200)))
					small[i] = make([]byte, len(raw[i]))
					large[i] = make([]byte, 65535)
				}
				tcp, udp := newTCPGROTable(), newUDPGROTable()
				var promotion groPromotion
				writes := make([]int, 0, count)
				b.ReportAllocs()
				b.ResetTimer()
				for n := 0; n < b.N; n++ {
					for i := range raw {
						copy(small[i], raw[i])
						if lazy {
							bufs[i] = small[i]
						} else {
							copy(large[i], small[i])
							bufs[i] = large[i][:len(small[i])]
						}
					}
					if lazy {
						promotion.begin(bufs)
						tcp.promotion = &promotion
						udp.promotion = &promotion
					}
					writes = writes[:0]
					if err := handleGRO(bufs, offset, tcp, udp, true, &writes); err != nil {
						b.Fatal(err)
					}
					tcp.reset()
					udp.reset()
					if lazy {
						promotion.finish(bufs)
					}
				}
				b.ReportMetric(float64(len(writes)), "writes/batch")
			})
		}
	}
}

// TestGROPromotionClose releases cached storage with the TUN write lock held.
func TestGROPromotionClose(t *testing.T) {
	t.Parallel()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	tun := &NativeTun{tunFile: w}
	tun.promotion.buffers[0] = make([]byte, 65536)
	if err := tun.Close(); err != nil {
		t.Fatal(err)
	}
	for _, buf := range tun.promotion.buffers {
		if buf != nil {
			t.Fatal("closed TUN retained scratch storage")
		}
	}
	if _, err := tun.Write([][]byte{make([]byte, 64)}, 16); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("write after close: %v", err)
	}
	tun.promotion.begin([][]byte{make([]byte, 64)})
	if tun.promotion.active {
		t.Fatal("closed workspace reactivated")
	}
}

// TestGROPromotionHeadroom preserves arbitrary caller headroom around the
// virtio header, including WireGuard's 16-byte transport offset.
func TestGROPromotionHeadroom(t *testing.T) {
	t.Parallel()
	for _, headroom := range []int{16, 32} {
		run := func(lazy bool) []byte {
			var bufs [][]byte
			for i := 0; i < 2; i++ {
				raw := tcp4Packet(ip4PortA, ip4PortB, header.TCPFlagAck, 100, uint32(1+i*100))
				size := headroom + len(raw) - offset
				capacity := 65535
				if lazy {
					capacity = size
				}
				buf := make([]byte, size, capacity)
				for j := 0; j < headroom; j++ {
					buf[j] = 0xa5
				}
				copy(buf[headroom:], raw[offset:])
				bufs = append(bufs, buf)
			}
			var promotion groPromotion
			tcp, udp := newTCPGROTable(), newUDPGROTable()
			if lazy {
				promotion.begin(bufs)
				tcp.promotion = &promotion
				udp.promotion = &promotion
			}
			var writes []int
			if err := handleGRO(bufs, headroom, tcp, udp, true, &writes); err != nil {
				t.Fatal(err)
			}
			if len(writes) != 1 {
				t.Fatal("packets did not merge")
			}
			result := bytes.Clone(bufs[writes[0]])
			if lazy {
				promotion.finish(bufs)
			}
			return result
		}
		if !bytes.Equal(run(false), run(true)) {
			t.Fatalf("headroom %d changed output", headroom)
		}
	}
}

// TestGROPromotionFullBuffer preserves the budget-managed full-buffer bound.
func TestGROPromotionFullBuffer(t *testing.T) {
	p := &groPromotion{}
	bufs := [][]byte{make([]byte, 1280, 65535)}
	p.begin(bufs)
	defer p.finish(bufs)
	if p.ensure(bufs, 0, 65536) || p.used != 0 {
		t.Fatal("full buffer triggered private allocation")
	}
}

// TestGROPromotionCapabilities keeps compact writes free of private growth.
func TestGROPromotionCapabilities(t *testing.T) {
	for _, plain := range []bool{false, true} {
		for _, framed := range []bool{false, true} {
			d := &NativeTun{noSegmentation: plain, vnetHdr: framed}
			caps := d.PacketBufferCapabilities()
			if caps.ReadConsumesWholePacket != plain || caps.WriteUsesPacketLength != (plain || framed) || caps.WriteMayGrowPacketStorage != (framed && !plain) {
				t.Fatalf("plain=%v framed=%v: %+v", plain, framed, caps)
			}
		}
	}
}

// TestGROPromotionWriteError releases borrowed references even if TUN I/O fails.
func TestGROPromotionWriteError(t *testing.T) {
	t.Parallel()
	d, _ := socketTun(t, false, true)
	if err := d.tunFile.Close(); err != nil {
		t.Fatal(err)
	}
	bufs := [][]byte{
		bytes.Clone(tcp4Packet(ip4PortA, ip4PortB, header.TCPFlagAck, 100, 1)),
		bytes.Clone(tcp4Packet(ip4PortA, ip4PortB, header.TCPFlagAck, 100, 101)),
	}
	original := append([][]byte(nil), bufs...)
	if _, err := d.Write(bufs, offset); err == nil {
		t.Fatal("closed file accepted write")
	}
	if d.promotion.buffers[0] == nil {
		t.Fatal("test did not exercise promotion")
	}
	if d.promotion.active || d.promotion.used != 0 {
		t.Fatal("write left active workspace")
	}
	for i := range bufs {
		if &bufs[i][0] != &original[i][0] || len(bufs[i]) != len(original[i]) || cap(bufs[i]) != cap(original[i]) {
			t.Fatal("write error changed caller header")
		}
	}
	for _, b := range d.promotion.originals {
		if b != nil {
			t.Fatal("write error retained borrowed storage")
		}
	}
}

// TestGROPromotionOversizedBatch refuses private growth beyond its fixed bound.
func TestGROPromotionOversizedBatch(t *testing.T) {
	t.Parallel()
	var p groPromotion
	bufs := make([][]byte, groPromotionMaxHeads+1)
	bufs[0] = make([]byte, 64)
	p.begin(bufs)
	defer p.finish(bufs)
	if p.ensure(bufs, 0, 128) || p.active || p.used != 0 {
		t.Fatal("oversized batch enabled promotion")
	}
}
