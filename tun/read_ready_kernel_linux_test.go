/* SPDX-License-Identifier: MIT */

package tun

import (
	"bytes"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/packetbudget"
)

// TestReadyBatchRealTUN verifies that several real kernel UDP frames queued
// before the read arrive together with complete payloads and valid checksums.
func TestReadyBatchRealTUN(t *testing.T) {
	if os.Getenv("WG_TUN_RECEIVE_GROUPING_TEST") != "1" {
		t.Skip("requires private network namespace")
	}
	budget, err := packetbudget.New(packetbudget.Config{MaxBytes: 1 << 20, ControlReserveBytes: 256 << 10, MaxCachedBytes: 65536, QueueEntries: 64})
	if err != nil {
		t.Fatal(err)
	}
	defer budget.Close()
	dev, err := CreateTUNWithOptions("sgrxready", 1280, Options{DisableSegmentationOffloads: true, ReceiveGrouping: true, ReadBatchPackets: 12, PacketBudget: budget})
	if err != nil {
		t.Fatal(err)
	}
	defer dev.Close()
	for _, args := range [][]string{{"link", "set", "lo", "up"}, {"link", "set", "sgrxready", "up"}, {"-4", "addr", "add", "198.19.240.1/24", "dev", "sgrxready"}} {
		if output, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("ip %v: %s %v", args, output, err)
		}
	}
	c, err := net.DialUDP("udp4", &net.UDPAddr{IP: net.ParseIP("198.19.240.1")}, &net.UDPAddr{IP: net.ParseIP("198.19.240.2"), Port: 54321})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for i := 0; i < 7; i++ {
		p := bytes.Repeat([]byte{byte(i)}, 1200)
		if n, err := c.Write(p); n != len(p) || err != nil {
			t.Fatal(n, err)
		}
	}
	bufs := make([][]byte, 12)
	sizes := make([]int, 12)
	for i := range bufs {
		bufs[i] = make([]byte, 2048)
	}
	if err := dev.File().SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	n, err := dev.Read(bufs, sizes, 16)
	if err != nil || n < 7 || n > 12 {
		t.Fatalf("real ready batch: n=%d error=%v", n, err)
	}
	matched := 0
	for i := 0; i < n; i++ {
		raw := bufs[i][16 : 16+sizes[i]]
		if raw[0]>>4 == 6 && len(raw) >= 40 && raw[6] == unix.IPPROTO_ICMPV6 {
			t.Logf("ordinary IPv6 link control frame: %d bytes", len(raw))
			continue
		}
		if len(raw) != 1228 || raw[0]>>4 != 4 || raw[9] != unix.IPPROTO_UDP || !bytes.Equal(raw[28:], bytes.Repeat([]byte{byte(matched)}, 1200)) {
			t.Fatalf("frame %d payload/header mismatch", i)
		}
		if !checksumValid(raw, 20, unix.IPPROTO_UDP, false) {
			t.Fatalf("frame %d checksum", i)
		}
		matched++
	}
	if matched != 7 {
		t.Fatalf("UDP frames %d", matched)
	}
	if err := dev.Close(); err != nil {
		t.Fatal(err)
	}
	if budget.Snapshot().Outstanding != 0 {
		t.Fatal("retained owners", budget.Snapshot())
	}
}

// TestReadyBatchRealIPv6TUN verifies that several real kernel UDP frames queued
// before the read arrive together with complete payloads and valid checksums.
func TestReadyBatchRealIPv6TUN(t *testing.T) {
	if os.Getenv("WG_TUN_RECEIVE_GROUPING_TEST") != "1" {
		t.Skip("requires private network namespace")
	}
	budget, err := packetbudget.New(packetbudget.Config{MaxBytes: 1 << 20, ControlReserveBytes: 256 << 10, MaxCachedBytes: 65536, QueueEntries: 64})
	if err != nil {
		t.Fatal(err)
	}
	defer budget.Close()
	dev, err := CreateTUNWithOptions("sgrxready", 1280, Options{DisableSegmentationOffloads: true, ReceiveGrouping: true, ReadBatchPackets: 12, PacketBudget: budget})
	if err != nil {
		t.Fatal(err)
	}
	defer dev.Close()
	for _, args := range [][]string{{"link", "set", "lo", "up"}, {"link", "set", "sgrxready", "up"}, {"-6", "addr", "add", "fd00:2590::1/64", "dev", "sgrxready", "nodad"}} {
		if output, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("ip %v: %s %v", args, output, err)
		}
	}
	c, err := net.DialUDP("udp6", &net.UDPAddr{IP: net.ParseIP("fd00:2590::1")}, &net.UDPAddr{IP: net.ParseIP("fd00:2590::2"), Port: 54321})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for i := 0; i < 7; i++ {
		p := bytes.Repeat([]byte{byte(i)}, 1200)
		if n, err := c.Write(p); n != len(p) || err != nil {
			t.Fatal(n, err)
		}
	}
	bufs := make([][]byte, 12)
	sizes := make([]int, 12)
	for i := range bufs {
		bufs[i] = make([]byte, 2048)
	}
	if err := dev.File().SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	n, err := dev.Read(bufs, sizes, 16)
	if err != nil || n < 7 || n > 12 {
		t.Fatalf("real ready batch: n=%d error=%v", n, err)
	}
	matched := 0
	for i := 0; i < n; i++ {
		raw := bufs[i][16 : 16+sizes[i]]
		if raw[0]>>4 == 6 && len(raw) >= 40 && raw[6] == unix.IPPROTO_ICMPV6 {
			t.Logf("ordinary IPv6 link control frame: %d bytes", len(raw))
			continue
		}
		if len(raw) != 1248 || raw[0]>>4 != 6 || raw[6] != unix.IPPROTO_UDP || !bytes.Equal(raw[48:], bytes.Repeat([]byte{byte(matched)}, 1200)) {
			t.Fatalf("frame %d payload/header mismatch", i)
		}
		if !checksumValid(raw, 40, unix.IPPROTO_UDP, true) {
			t.Fatalf("frame %d checksum", i)
		}
		matched++
	}
	if matched != 7 {
		t.Fatalf("UDP frames %d", matched)
	}
	if err := dev.Close(); err != nil {
		t.Fatal(err)
	}
	if budget.Snapshot().Outstanding != 0 {
		t.Fatal("retained owners", budget.Snapshot())
	}
}
