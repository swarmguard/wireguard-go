// SPDX-License-Identifier: MIT
package tun

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"sync"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/packetbudget"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// groupTestTun creates a bounded workspace and checks cleanup accounting.
func groupTestTun(t *testing.T) (*NativeTun, *packetbudget.Budget) {
	t.Helper()
	b, err := packetbudget.New(packetbudget.Config{MaxBytes: 1 << 20, ControlReserveBytes: 256 << 10, MaxCachedBytes: 1 << 16, QueueEntries: 64})
	if err != nil {
		t.Fatal(err)
	}
	d := &NativeTun{vnetHdr: true, noSegmentation: true}
	if err := d.initReceiveGrouping(b); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		d.closeReceiveGrouping()
		b.Close()
		if s := b.Snapshot(); s.ManagedBytes != 0 || s.Outstanding != 0 {
			t.Fatal(s)
		}
	})
	return d, b
}

// TestReceiveGroupingRoundTrip covers packet-sized ownership, chunking and TCP data.
func TestReceiveGroupingRoundTrip(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		for _, count := range []int{1, 2, 11, 12, 13, 25} {
			d, b := groupTestTun(t)
			packets := make([][]byte, count)
			before := make([][]byte, count)
			for i := range packets {
				p := tcp4Packet(ip4PortA, ip4PortB, header.TCPFlagAck, 1200, uint32(i*1200))
				if v6 {
					p = tcp6Packet(ip6PortA, ip6PortB, header.TCPFlagAck, 1200, uint32(i*1200))
				}
				packets[i] = bytes.Clone(p)
				before[i] = bytes.Clone(p)
			}
			writes := 0
			logical := 0
			n, err := d.writeGroupedTo(packets, offset, func(p []byte) (int, error) {
				writes++
				var h virtioNetHdr
				if e := decodeReceiveGroupHeader(&h, p); e != nil {
					t.Fatal(e)
				}
				if h.gsoType == 0 {
					logical++
					return len(p), nil
				}
				out := make([][]byte, 12)
				sz := make([]int, 12)
				for i := range out {
					out[i] = make([]byte, 2048)
				}
				native := bytes.Clone(p)
				h.encode(native)
				c, e := handleVirtioRead(native, out, sz, 0)
				if e != nil {
					t.Fatal(e)
				}
				for i := 0; i < c; i++ {
					iph := uint8(20)
					if v6 {
						iph = 40
					}
					if !checksumValid(out[i][:sz[i]], iph, unix.IPPROTO_TCP, v6) {
						t.Fatal("bad checksum")
					}
				}
				logical += c
				return len(p), nil
			})
			if err != nil || n <= 0 || writes != (count+11)/12 || logical != count {
				t.Fatalf("v6=%v count=%d writes=%d logical=%d n=%d err=%v", v6, count, writes, logical, n, err)
			}
			for i := range packets {
				if !bytes.Equal(packets[i], before[i]) {
					t.Fatal("borrowed input modified")
				}
			}
			if s := b.Snapshot(); s.Outstanding != 12 || s.DataBytes != 12*16384 {
				t.Fatal(s)
			}
		}
	}
}

// TestReceiveGroupingFallbackAndFailures preserves unrelated packets and write errors.
func TestReceiveGroupingFallbackAndFailures(t *testing.T) {
	d, _ := groupTestTun(t)
	packets := [][]byte{udp4PacketMutateIPFields(ip4PortA, ip4PortB, 30, nil), tcp4Packet(ip4PortA, ip4PortB, header.TCPFlagSyn, 0, 1), make([]byte, offset+20000)}
	calls := 0
	n, err := d.writeGroupedTo(packets, offset, func(p []byte) (int, error) {
		calls++
		if calls == 2 {
			return 0, syscall.EIO
		}
		return len(p), nil
	})
	if !errors.Is(err, syscall.EIO) || calls != 3 || n != len(packets[0])+len(packets[2]) {
		t.Fatalf("%d %d %v", n, calls, err)
	}
	calls = 0
	_, err = d.writeGroupedTo(packets, offset, func(p []byte) (int, error) { calls++; return 0, syscall.EBADFD })
	if err == nil || calls != 1 {
		t.Fatal(calls, err)
	}
	calls = 0
	_, err = d.writeGroupedTo(packets, offset+30000, func(p []byte) (int, error) { calls++; return len(p), nil })
	if !errors.Is(err, io.ErrShortBuffer) || calls != 0 {
		t.Fatal(calls, err)
	}
	p := tcp4Packet(ip4PortA, ip4PortB, header.TCPFlagAck, 1200, 1)
	calls = 0
	n, err = d.writeGroupedTo([][]byte{p, p}, offset, func(p []byte) (int, error) { calls++; return 7, nil })
	if err != nil || calls != 2 || n != 14 {
		t.Fatal(n, calls, err)
	}
}

// TestReceiveGroupingReservationRollback covers construction and advertised capabilities.
func TestReceiveGroupingReservationRollback(t *testing.T) {
	b, _ := packetbudget.New(packetbudget.Config{MaxBytes: 200 << 10, ControlReserveBytes: 32 << 10, MaxCachedBytes: 1 << 16, QueueEntries: 64})
	d := &NativeTun{}
	if err := d.initReceiveGrouping(b); !errors.Is(err, packetbudget.ErrExhausted) {
		t.Fatal(err)
	}
	if b.Snapshot().Outstanding != 0 || d.receiveGrouping != nil {
		t.Fatal(b.Snapshot())
	}
	b.Close()
	if b.Snapshot().ManagedBytes != 0 {
		t.Fatal(b.Snapshot())
	}
	d, b = groupTestTun(t)
	flags := []int{}
	d.closeReceiveGrouping()
	if err := d.configureOffloads(unix.IFF_VNET_HDR, Options{DisableSegmentationOffloads: true, ReceiveGrouping: true, PacketBudget: b}, func(v int) error { flags = append(flags, v); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(flags) != 1 || flags[0] != unix.TUN_F_CSUM || d.BatchSize() != 1 || !d.PacketBufferCapabilities().ReadConsumesWholePacket || !d.PacketBufferCapabilities().WriteUsesPacketLength {
		t.Fatal(flags, d.PacketBufferCapabilities())
	}
}

// TestReceiveGroupingConcurrentClose checks serialized peers and exactly-once cleanup.
func TestReceiveGroupingConcurrentClose(t *testing.T) {
	d, b := groupTestTun(t)
	r, w, e := os.Pipe()
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	d.tunFile = w
	drain := make(chan struct{})
	go func() { io.Copy(io.Discard, r); close(drain) }()
	p := tcp4Packet(ip4PortA, ip4PortB, header.TCPFlagAck, 1200, 1)
	q := tcp4Packet(ip4PortA, ip4PortB, header.TCPFlagAck, 1200, 1201)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 30; j++ {
				d.Write([][]byte{p, q}, offset)
			}
		}()
	}
	d.Close()
	d.Close()
	wg.Wait()
	<-drain
	if b.Snapshot().Outstanding != 0 {
		t.Fatal(b.Snapshot())
	}
}

// TestReceiveGroupingCapacityLimit splits groups instead of growing workspace.
func TestReceiveGroupingCapacityLimit(t *testing.T) {
	d, b := groupTestTun(t)
	packets := make([][]byte, 12)
	for i := range packets {
		packets[i] = tcp6Packet(ip6PortA, ip6PortB, header.TCPFlagAck, 1920, uint32(i*1920))
	}
	writes := 0
	logical := 0
	_, err := d.writeGroupedTo(packets, offset, func(p []byte) (int, error) {
		writes++
		if len(p) > receiveGroupBytes {
			t.Fatal("workspace grew", len(p))
		}
		var h virtioNetHdr
		if e := decodeReceiveGroupHeader(&h, p); e != nil {
			t.Fatal(e)
		}
		if h.gsoType != 0 {
			logical += (len(p) - virtioNetHdrLen - int(h.hdrLen) + int(h.gsoSize) - 1) / int(h.gsoSize)
		} else {
			logical++
		}
		return len(p), nil
	})
	if err != nil || writes != 2 || logical != 12 || b.Snapshot().DataBytes != 12*receiveGroupBytes {
		t.Fatal(writes, logical, err, b.Snapshot())
	}
}

// decodeReceiveGroupHeader reads compact's portable little-endian framing.
func decodeReceiveGroupHeader(h *virtioNetHdr, p []byte) error {
	if len(p) < virtioNetHdrLen {
		return io.ErrShortBuffer
	}
	h.flags, h.gsoType = p[0], p[1]
	h.hdrLen = binary.LittleEndian.Uint16(p[2:4])
	h.gsoSize = binary.LittleEndian.Uint16(p[4:6])
	h.csumStart = binary.LittleEndian.Uint16(p[6:8])
	h.csumOffset = binary.LittleEndian.Uint16(p[8:10])
	return nil
}

// TestReceiveGroupingHeaderOrder checks both source byte orders without changing
// the existing normal-mode header format or bytes after the header.
func TestReceiveGroupingHeaderOrder(t *testing.T) {
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		frame := bytes.Repeat([]byte{0xa5}, 32)
		values := []uint16{40, 1200, 20, 16}
		for i, value := range values {
			order.PutUint16(frame[2+i*2:], value)
		}
		receiveGroupHeaderLittleEndian(frame, order)
		for i, value := range values {
			if got := binary.LittleEndian.Uint16(frame[2+i*2:]); got != value {
				t.Fatalf("%T field %d: %d != %d", order, i, got, value)
			}
		}
		if !bytes.Equal(frame[:2], []byte{0xa5, 0xa5}) || !bytes.Equal(frame[10:], bytes.Repeat([]byte{0xa5}, 22)) {
			t.Fatal("non-header bytes changed")
		}
	}
}

// TestReceiveGroupingInvalidOptions rejects incompatible requests before
// changing kernel offloads or acquiring workspace.
func TestReceiveGroupingInvalidOptions(t *testing.T) {
	_, budget := groupTestTun(t)
	for _, tc := range []struct {
		name    string
		flags   uint16
		options Options
	}{
		{"segmentation", unix.IFF_VNET_HDR, Options{ReceiveGrouping: true, PacketBudget: budget}},
		{"unframed", 0, Options{DisableSegmentationOffloads: true, ReceiveGrouping: true, PacketBudget: budget}},
		{"no budget", unix.IFF_VNET_HDR, Options{DisableSegmentationOffloads: true, ReceiveGrouping: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := budget.Snapshot()
			d := &NativeTun{}
			err := d.configureOffloads(tc.flags, tc.options, func(int) error { t.Fatal("unexpected ioctl"); return nil })
			if err == nil || d.receiveGrouping != nil || budget.Snapshot() != before {
				t.Fatal(err, budget.Snapshot())
			}
		})
	}
	d := &NativeTun{}
	before := budget.Snapshot()
	err := d.configureOffloads(unix.IFF_VNET_HDR, Options{DisableSegmentationOffloads: true, ReceiveGrouping: true, PacketBudget: budget}, func(int) error { return syscall.EPERM })
	if !errors.Is(err, syscall.EPERM) || d.receiveGrouping != nil || budget.Snapshot() != before {
		t.Fatal(err, budget.Snapshot())
	}
}

// TestReceiveGroupingPartialWrites never retries a written group and clears
// scratch state even when the descriptor closes partway through a batch.
func TestReceiveGroupingPartialWrites(t *testing.T) {
	for _, fail := range []error{syscall.EIO, syscall.EBADFD} {
		t.Run(fail.Error(), func(t *testing.T) {
			d, _ := groupTestTun(t)
			var packets [][]byte
			for flow := 0; flow < 3; flow++ {
				src := netip.AddrPortFrom(ip4PortA.Addr(), ip4PortA.Port()+uint16(flow))
				for i := 0; i < 2; i++ {
					packets = append(packets, tcp4Packet(src, ip4PortB, header.TCPFlagAck, 1200, uint32(i*1200)))
				}
			}
			calls, want := 0, 0
			n, err := d.writeGroupedTo(packets, offset, func(p []byte) (int, error) {
				calls++
				if calls == 2 {
					return 7, fail
				}
				want += len(p)
				return len(p), nil
			})
			wantCalls, wantErr := 3, fail
			if fail == syscall.EBADFD {
				wantCalls, wantErr = 2, os.ErrClosed
			}
			if n != want || calls != wantCalls || !errors.Is(err, wantErr) {
				t.Fatal(n, want, calls, err)
			}
			g := d.receiveGrouping
			if len(g.tcp.itemsByFlow) != 0 || len(g.udp.itemsByFlow) != 0 || len(g.indexes) != 0 {
				t.Fatal("retained batch state")
			}
			for _, p := range g.bufs {
				if p != nil {
					t.Fatal("retained slice")
				}
			}
			if _, err := d.writeGroupedTo(packets[:2], offset, func(p []byte) (int, error) { return len(p), nil }); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// TestReceiveGroupingOffsets leaves packet-sized caller storage unchanged,
// including prefixes larger than the native virtio header.
func TestReceiveGroupingOffsets(t *testing.T) {
	for _, prefix := range []int{10, 16, 32} {
		t.Run(fmt.Sprint(prefix), func(t *testing.T) {
			d, _ := groupTestTun(t)
			packets, originals := make([][]byte, 2), make([][]byte, 2)
			for i := range packets {
				packet := tcp4Packet(ip4PortA, ip4PortB, header.TCPFlagAck, 1200, uint32(i*1200))
				packets[i] = make([]byte, prefix+len(packet)-offset, 2048)
				copy(packets[i][prefix:], packet[offset:])
				originals[i] = bytes.Clone(packets[i])
			}
			writes := 0
			_, err := d.writeGroupedTo(packets, prefix, func(p []byte) (int, error) {
				writes++
				if len(p) != virtioNetHdrLen+40+2400 {
					t.Fatal(len(p))
				}
				return len(p), nil
			})
			if err != nil || writes != 1 {
				t.Fatal(writes, err)
			}
			for i := range packets {
				if !bytes.Equal(packets[i], originals[i]) {
					t.Fatal("caller bytes changed")
				}
			}
		})
	}
}
