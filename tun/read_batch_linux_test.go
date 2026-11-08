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
)

// TestReadyBatchBoundAndPartial checks immediate draining, the fixed work bound,
// offsets, full-frame oversize rejection and progress after a rejected frame.
func TestReadyBatchBoundAndPartial(t *testing.T) {
	for _, framed := range []bool{false, true} {
		frame := func(n int) []byte {
			p := bytes.Repeat([]byte{0x42}, n)
			if framed {
				p = append(make([]byte, virtioNetHdrLen), p...)
			}
			return p
		}
		for _, count := range []int{0, 1, 7, 12, 16} {
			packets := make([][]byte, count)
			for i := range packets {
				packets[i] = frame(1280)
			}
			reads := 0
			read := func(p []byte) (int, error) {
				reads++
				if len(packets) == 0 {
					return 0, unix.EAGAIN
				}
				n := copy(p, packets[0])
				packets = packets[1:]
				return n, nil
			}
			bufs := make([][]byte, 16)
			sizes := make([]int, 16)
			for i := range bufs {
				bufs[i] = make([]byte, 2048)
			}
			n, err := readReadyBatch(12, read, make([]byte, 65545), framed, bufs, sizes, 16)
			if n != min(count, 12) || err != nil {
				t.Fatalf("count %d: n=%d err=%v", count, n, err)
			}
			if reads > 13 || len(packets) != max(0, count-12) {
				t.Fatal("work bound", reads, len(packets))
			}
			for i := 0; i < n; i++ {
				if sizes[i] != 1280 || !bytes.Equal(bufs[i][16:1296], bytes.Repeat([]byte{0x42}, 1280)) {
					t.Fatal("payload")
				}
			}
		}
		packets := [][]byte{frame(1280), frame(4096), frame(1280)}
		read := func(p []byte) (int, error) {
			if len(packets) == 0 {
				return 0, unix.EAGAIN
			}
			n := copy(p, packets[0])
			packets = packets[1:]
			return n, nil
		}
		bufs := [][]byte{make([]byte, 2048), make([]byte, 2048), make([]byte, 2048)}
		sizes := make([]int, 3)
		n, err := readReadyBatch(12, read, make([]byte, 65545), framed, bufs, sizes, 16)
		if n != 1 || !errors.Is(err, io.ErrShortBuffer) {
			t.Fatal("partial oversize", n, err)
		}
		n, err = readReadyBatch(12, read, make([]byte, 65545), framed, bufs, sizes, 16)
		if n != 1 || err != nil {
			t.Fatal("oversize recovery", n, err)
		}
	}
}

// TestReadyBatchErrors preserves valid packets before errors and retries EINTR.
func TestReadyBatchErrors(t *testing.T) {
	calls := 0
	read := func(p []byte) (int, error) {
		calls++
		switch calls {
		case 1:
			return 0, unix.EINTR
		case 2:
			return copy(p, []byte{1, 2, 3}), nil
		default:
			return 0, unix.EIO
		}
	}
	bufs := [][]byte{make([]byte, 64), make([]byte, 64)}
	sizes := make([]int, 2)
	n, err := readReadyBatch(12, read, make([]byte, 65545), false, bufs, sizes, 16)
	if n != 1 || !errors.Is(err, unix.EIO) || sizes[0] != 3 {
		t.Fatal(n, err, sizes)
	}
	if n, err := readReadyBatch(12, read, make([]byte, 65545), false, nil, nil, 0); n != 0 || !errors.Is(err, io.ErrShortBuffer) {
		t.Fatal(n, err)
	}
}

// TestReadyBatchDescriptor checks real nonblocking descriptor draining, deadlines,
// oversized frame recovery and close while the first frame is still pending.
func TestReadyBatchDescriptor(t *testing.T) {
	dev, peer := socketTun(t, true, true)
	dev.readBatchPackets = 12
	frame := func(n int) []byte { return append(make([]byte, virtioNetHdrLen), bytes.Repeat([]byte{0x42}, n)...) }
	bufs := make([][]byte, 12)
	sizes := make([]int, 12)
	for i := range bufs {
		bufs[i] = make([]byte, 2048)
	}
	for i := 0; i < 7; i++ {
		if _, err := peer.Write(frame(1280)); err != nil {
			t.Fatal(err)
		}
	}
	if n, err := dev.Read(bufs, sizes, 16); n != 7 || err != nil {
		t.Fatal("ready drain", n, err)
	}
	for i := 0; i < 7; i++ {
		if sizes[i] != 1280 || !bytes.Equal(bufs[i][16:1296], bytes.Repeat([]byte{0x42}, 1280)) {
			t.Fatal("payload")
		}
	}
	for _, length := range []int{1280, 4096, 1280} {
		if _, err := peer.Write(frame(length)); err != nil {
			t.Fatal(err)
		}
	}
	if n, err := dev.Read(bufs, sizes, 16); n != 1 || !errors.Is(err, io.ErrShortBuffer) {
		t.Fatal("partial oversized", n, err)
	}
	if n, err := dev.Read(bufs, sizes, 16); n != 1 || err != nil {
		t.Fatal("recovery", n, err)
	}
	if err := dev.File().SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if n, err := dev.Read(bufs, sizes, 16); n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal("deadline", n, err)
	}
	if err := dev.File().SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := dev.Read(bufs, sizes, 16); done <- err }()
	select {
	case err := <-done:
		t.Fatalf("returned before close: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	if err := dev.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, os.ErrClosed) {
			t.Fatal("closed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("blocked after close")
	}
}

// TestReadyBatchCapacity checks each caller limit without consuming a packet
// when no output slot is available.
func TestReadyBatchCapacity(t *testing.T) {
	for _, tc := range []struct {
		name                         string
		buffers, sizes, offset, want int
		wantErr                      error
	}{
		{"one buffer", 1, 12, 16, 1, nil},
		{"one size", 12, 1, 16, 1, nil},
		{"no buffers", 0, 12, 16, 0, io.ErrShortBuffer},
		{"no sizes", 12, 0, 16, 0, io.ErrShortBuffer},
		{"negative offset", 12, 12, -1, 0, io.ErrShortBuffer},
		{"offset past end", 12, 12, 2049, 0, io.ErrShortBuffer},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bufs := make([][]byte, tc.buffers)
			for i := range bufs {
				bufs[i] = make([]byte, 2048)
			}
			sizes := make([]int, tc.sizes)
			calls := 0
			n, err := readReadyBatch(12, func(p []byte) (int, error) {
				calls++
				return copy(p, []byte{1, 2, 3}), nil
			}, make([]byte, 65545), false, bufs, sizes, tc.offset)
			if n != tc.want || !errors.Is(err, tc.wantErr) || calls != tc.want {
				t.Fatalf("n=%d err=%v calls=%d", n, err, calls)
			}
		})
	}
	bufs := [][]byte{make([]byte, 2048), make([]byte, 8)}
	calls := 0
	n, err := readReadyBatch(12, func(p []byte) (int, error) {
		calls++
		return copy(p, []byte{1, 2, 3}), nil
	}, make([]byte, 65545), false, bufs, make([]int, 2), 16)
	if n != 1 || !errors.Is(err, io.ErrShortBuffer) || calls != 1 {
		t.Fatalf("partial capacity: n=%d err=%v calls=%d", n, err, calls)
	}
}

// TestReadyBatchFraming keeps checksum completion and framing rejection identical
// to single-packet reads, including recovery after consuming a malformed frame.
func TestReadyBatchFraming(t *testing.T) {
	for _, kind := range []string{"tcp4", "tcp6", "udp4", "udp6"} {
		t.Run(kind, func(t *testing.T) {
			frames := make([][]byte, 4)
			want := make([][]byte, len(frames))
			for i := range frames {
				frame := batchAggregate(kind, 1)
				// A single segment with a partial checksum, as a checksum-only
				// TUN can supply. Native compact framing is little endian.
				frame[1] = unix.VIRTIO_NET_HDR_GSO_NONE
				for at := 2; at < virtioNetHdrLen; at += 2 {
					v := binary.NativeEndian.Uint16(frame[at:])
					binary.LittleEndian.PutUint16(frame[at:], v)
				}
				frames[i] = bytes.Clone(frame)
				out := make([]byte, 2048)
				size := []int{0}
				if _, err := readPlain(frame, true, out, size, 16); err != nil {
					t.Fatal(err)
				}
				want[i] = out[16 : 16+size[0]]
			}
			bufs := make([][]byte, 4)
			for i := range bufs {
				bufs[i] = make([]byte, 2048)
			}
			sizes := make([]int, 4)
			at := 0
			n, err := readReadyBatch(12, func(p []byte) (int, error) {
				if at == len(frames) {
					return 0, unix.EAGAIN
				}
				n := copy(p, frames[at])
				at++
				return n, nil
			}, make([]byte, 65545), true, bufs, sizes, 16)
			if n != 4 || err != nil {
				t.Fatal(n, err)
			}
			for i := range want {
				if !bytes.Equal(bufs[i][16:16+sizes[i]], want[i]) {
					t.Fatalf("packet %d", i)
				}
			}
		})
	}
	for _, bad := range [][]byte{nil, {1}, make([]byte, virtioNetHdrLen), {0, unix.VIRTIO_NET_HDR_GSO_TCPV4, 0, 0, 0, 0, 0, 0, 0, 0, 1}} {
		t.Run(fmt.Sprintf("malformed-%x", bad), func(t *testing.T) {
			valid := append(make([]byte, virtioNetHdrLen), 1, 2, 3)
			frames := [][]byte{valid, bad, valid}
			read := func(p []byte) (int, error) {
				if len(frames) == 0 {
					return 0, unix.EAGAIN
				}
				n := copy(p, frames[0])
				frames = frames[1:]
				return n, nil
			}
			bufs := [][]byte{make([]byte, 2048), make([]byte, 2048), make([]byte, 2048)}
			sizes := make([]int, 3)
			if n, err := readReadyBatch(12, read, make([]byte, 65545), true, bufs, sizes, 16); n != 1 || err == nil {
				t.Fatal(n, err)
			}
			if n, err := readReadyBatch(12, read, make([]byte, 65545), true, bufs, sizes, 16); n != 1 || err != nil {
				t.Fatal(n, err)
			}
		})
	}
}

// TestReadyBatchWaitForFirst checks the RawConn callback's empty-queue path:
// it must wait for a packet, then return without waiting to fill the batch.
func TestReadyBatchWaitForFirst(t *testing.T) {
	dev, peer := socketTun(t, true, false)
	dev.readBatchPackets = 12
	bufs := [][]byte{make([]byte, 2048), make([]byte, 2048)}
	sizes := make([]int, 2)
	done := make(chan error, 1)
	go func() {
		n, err := dev.Read(bufs, sizes, 16)
		if err == nil && (n != 1 || sizes[0] != 3 || !bytes.Equal(bufs[0][16:19], []byte{1, 2, 3})) {
			err = fmt.Errorf("n=%d sizes=%v", n, sizes)
		}
		done <- err
	}()
	select {
	case err := <-done:
		t.Fatalf("returned before first packet: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	if _, err := peer.Write([]byte{1, 2, 3}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("waited to fill batch")
	}
}

// TestReadyBatchConfiguredLimit checks limits above and below the CC100 value.
func TestReadyBatchConfiguredLimit(t *testing.T) {
	for _, limit := range []int{1, 2, 12, 32, 64, 128} {
		bufs := make([][]byte, 128)
		for i := range bufs {
			bufs[i] = make([]byte, 64)
		}
		calls := 0
		n, err := readReadyBatch(limit, func(p []byte) (int, error) {
			calls++
			return copy(p, []byte{byte(calls)}), nil
		}, make([]byte, 65545), false, bufs, make([]int, 128), 16)
		if n != limit || calls != limit || err != nil {
			t.Fatalf("limit=%d n=%d calls=%d err=%v", limit, n, calls, err)
		}
	}
}

// TestReadyBatchOptions checks opt-in, default compatibility and validation.
func TestReadyBatchOptions(t *testing.T) {
	for _, limit := range []int{-1, 0, 1, 2, 12, 64, 128, 129} {
		for _, group := range []bool{false, true} {
			d, budget := groupTestTun(t)
			d.closeReceiveGrouping()
			err := d.configureOffloads(unix.IFF_VNET_HDR, Options{
				DisableSegmentationOffloads: true, ReceiveGrouping: group,
				ReadBatchPackets: limit, PacketBudget: budget,
			}, func(int) error { return nil })
			invalid := limit < 0 || limit > 128 || (limit > 1 && !group)
			if (err != nil) != invalid {
				t.Fatalf("limit=%d group=%t err=%v", limit, group, err)
			}
			if !invalid && d.readBatchPackets != max(1, limit) {
				t.Fatal("read limit", d.readBatchPackets)
			}
			if invalid && budget.Snapshot().Outstanding != 0 {
				t.Fatal("allocation before validation")
			}
		}
	}
}
