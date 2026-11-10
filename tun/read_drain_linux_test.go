// SPDX-License-Identifier: MIT

package tun

import (
	"bytes"
	"errors"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// drainTestTun supplies packet records through a nonblocking datagram socket.
func drainTestTun(t *testing.T) (*NativeTun, int) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	file := os.NewFile(uintptr(fds[0]), "drain-test")
	t.Cleanup(func() { file.Close(); unix.Close(fds[1]) })
	return &NativeTun{tunFile: file, vnetHdr: true}, fds[1]
}

// drainTestRecord builds a plain packet or a two-segment TCP GSO record.
func drainTestRecord(gso bool, id byte) []byte {
	packet := make([]byte, 72)
	packet[0] = 0x45
	packet[8] = 64
	packet[9] = 6
	packet[12] = 10
	packet[16] = 11
	packet[32] = 0x50
	packet[71] = id
	record := make([]byte, virtioNetHdrLen+len(packet))
	if gso {
		hdr := virtioNetHdr{gsoType: unix.VIRTIO_NET_HDR_GSO_TCPV4, gsoSize: 16, csumStart: 20, csumOffset: 16, hdrLen: 72}
		hdr.encode(record)
	}
	copy(record[virtioNetHdrLen:], packet)
	return record
}

// drainTestRead bounds waiting so an accidental second blocking read fails.
func drainTestRead(t *testing.T, tun *NativeTun, bufs [][]byte, sizes []int) int {
	t.Helper()
	type result struct {
		n   int
		err error
	}
	done := make(chan result, 1)
	go func() { n, err := tun.Read(bufs, sizes, 0); done <- result{n, err} }()
	select {
	case r := <-done:
		if r.err != nil {
			t.Fatal(r.err)
		}
		return r.n
	case <-time.After(time.Second):
		tun.tunFile.Close()
		t.Fatal("read waited despite an available packet")
		return 0
	}
}

// TestReadDrainBounded preserves order and leaves records beyond the limit queued.
func TestReadDrainBounded(t *testing.T) {
	tun, fd := drainTestTun(t)
	for i := byte(1); i <= 5; i++ {
		if _, err := unix.Write(fd, drainTestRecord(false, i)); err != nil {
			t.Fatal(err)
		}
	}
	bufs := make([][]byte, 8)
	for i := range bufs {
		bufs[i] = make([]byte, 128)
	}
	sizes := make([]int, 8)
	if n := drainTestRead(t, tun, bufs, sizes); n != 4 {
		t.Fatalf("got %d, want 4", n)
	}
	for i := 0; i < 4; i++ {
		if bufs[i][71] != byte(i+1) {
			t.Fatal("packet order changed")
		}
	}
	if n := drainTestRead(t, tun, bufs, sizes); n != 1 || bufs[0][71] != 5 {
		t.Fatal("queued final packet lost")
	}
}

// TestReadDrainPendingGSO defers a whole record without corrupting or losing it.
func TestReadDrainPendingGSO(t *testing.T) {
	tun, fd := drainTestTun(t)
	for _, r := range [][]byte{drainTestRecord(false, 1), drainTestRecord(false, 2), drainTestRecord(true, 3)} {
		if _, err := unix.Write(fd, r); err != nil {
			t.Fatal(err)
		}
	}
	bufs := [][]byte{make([]byte, 128), make([]byte, 128), make([]byte, 128)}
	sizes := make([]int, 3)
	if n := drainTestRead(t, tun, bufs, sizes); n != 2 {
		t.Fatalf("got %d, want 2", n)
	}
	if tun.pendingRead == 0 {
		t.Fatal("overflow record not retained")
	}
	expected := [][]byte{make([]byte, 128), make([]byte, 128)}
	wantSizes := make([]int, 2)
	if _, err := handleVirtioRead(drainTestRecord(true, 3), expected, wantSizes, 0); err != nil {
		t.Fatal(err)
	}
	if n := drainTestRead(t, tun, bufs, sizes); n != 2 {
		t.Fatalf("got %d, want 2", n)
	}
	for i := 0; i < 2; i++ {
		if sizes[i] != wantSizes[i] || !bytes.Equal(bufs[i][:sizes[i]], expected[i][:wantSizes[i]]) {
			t.Fatal("deferred GSO record changed")
		}
	}
	if tun.pendingRead != 0 {
		t.Fatal("pending record not consumed")
	}
}

// TestReadDrainClose interrupts an idle first read through the runtime poller.
func TestReadDrainClose(t *testing.T) {
	tun, _ := drainTestTun(t)
	done := make(chan error, 1)
	go func() { _, err := tun.Read([][]byte{make([]byte, 128)}, make([]int, 1), 0); done <- err }()
	tun.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected close error")
		}
	case <-time.After(time.Second):
		t.Fatal("close did not unblock read")
	}
}

// TestReadDrainOversizedRecord preserves the recoverable error used by the
// device read loop and consumes a record that cannot fit even an empty batch.
func TestReadDrainOversizedRecord(t *testing.T) {
	tun, fd := drainTestTun(t)
	for _, packet := range [][]byte{drainTestRecord(true, 1), drainTestRecord(false, 2)} {
		if _, err := unix.Write(fd, packet); err != nil {
			t.Fatal(err)
		}
	}
	bufs := [][]byte{make([]byte, 128)}
	sizes := make([]int, 1)
	n, err := tun.Read(bufs, sizes, 0)
	if n != 0 || !errors.Is(err, ErrTooManySegments) {
		t.Fatalf("Read = %d, %v", n, err)
	}
	if tun.pendingRead != 0 {
		t.Fatal("impossible record retained indefinitely")
	}
	if n := drainTestRead(t, tun, bufs, sizes); n != 1 || bufs[0][71] != 2 {
		t.Fatal("next valid packet lost")
	}
}

// TestReadDrainMalformedRecord preserves earlier packets when a later record
// fails validation, without panicking or looping on a zero GSO segment size.
func TestReadDrainMalformedRecord(t *testing.T) {
	zeroSize := drainTestRecord(true, 1)
	zeroSize[4], zeroSize[5] = 0, 0
	for name, packet := range map[string][]byte{
		"short header":      {1, 2},
		"empty payload":     make([]byte, virtioNetHdrLen),
		"zero segment size": zeroSize,
	} {
		t.Run(name, func(t *testing.T) {
			tun, fd := drainTestTun(t)
			for _, record := range [][]byte{drainTestRecord(false, 7), packet} {
				if _, err := unix.Write(fd, record); err != nil {
					t.Fatal(err)
				}
			}
			bufs := [][]byte{make([]byte, 128), make([]byte, 128), make([]byte, 128)}
			n, err := tun.Read(bufs, make([]int, 3), 0)
			if n != 1 || err == nil || bufs[0][71] != 7 {
				t.Fatalf("Read = %d, %v", n, err)
			}
		})
	}
}

// TestReadDrainCloseDiscardsPending prevents a retained record from being
// returned after Close has completed.
func TestReadDrainCloseDiscardsPending(t *testing.T) {
	tun, _ := drainTestTun(t)
	tun.pendingRead = copy(tun.readBuff[:], drainTestRecord(true, 1))
	if err := tun.Close(); err != nil {
		t.Fatal(err)
	}
	if tun.pendingRead != 0 {
		t.Fatal("closed device retained input")
	}
	n, err := tun.Read([][]byte{make([]byte, 128), make([]byte, 128)}, make([]int, 2), 0)
	if n != 0 || !errors.Is(err, os.ErrClosed) {
		t.Fatalf("Read = %d, %v", n, err)
	}
}

// TestReadDrainOffset preserves caller-owned prefixes while combining records.
func TestReadDrainOffset(t *testing.T) {
	tun, fd := drainTestTun(t)
	for i := byte(1); i <= 2; i++ {
		if _, err := unix.Write(fd, drainTestRecord(false, i)); err != nil {
			t.Fatal(err)
		}
	}
	bufs := [][]byte{bytes.Repeat([]byte{0xaa}, 128), bytes.Repeat([]byte{0xaa}, 128)}
	sizes := make([]int, 2)
	n, err := tun.Read(bufs, sizes, 16)
	if n != 2 || err != nil {
		t.Fatalf("Read = %d, %v", n, err)
	}
	for i := range bufs {
		if sizes[i] != 72 || bufs[i][16+71] != byte(i+1) || !bytes.Equal(bufs[i][:16], bytes.Repeat([]byte{0xaa}, 16)) {
			t.Fatal("offset or packet contents changed")
		}
	}
}
