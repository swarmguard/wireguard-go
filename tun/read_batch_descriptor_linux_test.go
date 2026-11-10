/* SPDX-License-Identifier: MIT */

package tun

import (
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestReadyReaderDescriptorGuard preserves immediate single-packet reads when
// a caller supplies a blocking descriptor, without changing descriptor flags.
func TestReadyReaderDescriptorGuard(t *testing.T) {
	for _, nonblocking := range []bool{true, false} {
		name := "blocking"
		kind := unix.SOCK_DGRAM | unix.SOCK_CLOEXEC
		if nonblocking {
			name = "nonblocking"
			kind |= unix.SOCK_NONBLOCK
		}
		t.Run(name, func(t *testing.T) {
			fds, err := unix.Socketpair(unix.AF_UNIX, kind, 0)
			if err != nil {
				t.Fatal(err)
			}
			file := os.NewFile(uintptr(fds[0]), "ready-guard")
			peer := os.NewFile(uintptr(fds[1]), "ready-peer")
			defer file.Close()
			defer peer.Close()
			dev, budget := groupTestTun(t)
			dev.closeReceiveGrouping()
			dev.tunFile = file
			dev.errors = make(chan error, 1)
			if err := dev.configureOffloads(unix.IFF_VNET_HDR, Options{DisableSegmentationOffloads: true, ReceiveGrouping: true, ReadBatchPackets: 12, PacketBudget: budget}, func(int) error { return nil }); err != nil {
				t.Fatal(err)
			}
			before, err := unix.FcntlInt(uintptr(fds[0]), unix.F_GETFL, 0)
			if err != nil {
				t.Fatal(err)
			}
			if err = dev.configureReadyReader(uintptr(fds[0])); err != nil {
				t.Fatal(err)
			}
			after, err := unix.FcntlInt(uintptr(fds[0]), unix.F_GETFL, 0)
			if err != nil {
				t.Fatal(err)
			}
			want := 1
			if nonblocking {
				want = 12
			}
			if dev.readBatchPackets != want || dev.BatchSize() != want || before != after {
				t.Fatal("selection or descriptor flags changed", dev.readBatchPackets, before, after)
			}
			bufs := make([][]byte, 12)
			sizes := make([]int, 12)
			for i := range bufs {
				bufs[i] = make([]byte, 2048)
			}
			if _, err = peer.Write(append(make([]byte, virtioNetHdrLen), 1, 2, 3)); err != nil {
				t.Fatal(err)
			}
			type result struct {
				n   int
				err error
			}
			done := make(chan result, 1)
			go func() { n, err := dev.Read(bufs, sizes, 0); done <- result{n, err} }()
			select {
			case r := <-done:
				if r.n != 1 || r.err != nil || sizes[0] != 3 {
					t.Fatal(r, sizes)
				}
			case <-time.After(time.Second):
				for i := 1; i < 12; i++ {
					peer.Write(append(make([]byte, virtioNetHdrLen), 1, 2, 3))
				}
				select {
				case <-done:
				case <-time.After(time.Second):
				}
				t.Fatal("reader waited for another packet")
			}
		})
	}
}

// TestReadyReaderDescriptorGuardErrors rejects unknown flags only when the
// batch reader was requested; the ordinary path remains unchanged.
func TestReadyReaderDescriptorGuardErrors(t *testing.T) {
	dev := &NativeTun{readBatchPackets: 12}
	if err := dev.configureReadyReader(^uintptr(0)); err == nil {
		t.Fatal("invalid descriptor accepted")
	}
	dev.readBatchPackets = 1
	if err := dev.configureReadyReader(^uintptr(0)); err != nil {
		t.Fatal("ordinary reader inspected descriptor", err)
	}
}
