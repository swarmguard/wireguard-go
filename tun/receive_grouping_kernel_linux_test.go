// SPDX-License-Identifier: MIT
package tun

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/packetbudget"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// TestReceiveGroupingKernel checks real kernel TCP delivery with checksum-only TUN reads.
// The runner must use a private network namespace; no production routes are touched.
func TestReceiveGroupingKernel(t *testing.T) {
	if os.Getenv("WG_TUN_RECEIVE_GROUPING_TEST") != "1" {
		t.Skip("requires isolated Linux network namespace")
	}
	// Failed creation must return reservations and close the owned TUN fd.
	for _, tc := range []struct {
		name                  string
		maximum, reserve, mtu int
		exhausted             bool
	}{
		{"budget", 200 << 10, 32 << 10, 1280, true},
		{"mtu", 1 << 20, 256 << 10, 1 << 30, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			budget, err := packetbudget.New(packetbudget.Config{MaxBytes: tc.maximum, ControlReserveBytes: tc.reserve, MaxCachedBytes: 65536, QueueEntries: 64})
			if err != nil {
				t.Fatal(err)
			}
			defer budget.Close()
			dev, err := CreateTUNWithOptions("sgrxfail", tc.mtu, Options{DisableSegmentationOffloads: true, ReceiveGrouping: true, PacketBudget: budget})
			if err == nil {
				dev.Close()
				t.Fatal("unexpected startup success")
			}
			if tc.exhausted && !errors.Is(err, packetbudget.ErrExhausted) {
				t.Fatal(err)
			}
			if budget.Snapshot().Outstanding != 0 {
				t.Fatal(budget.Snapshot())
			}
			if _, err := net.InterfaceByName("sgrxfail"); err == nil {
				t.Fatal("failed startup retained TUN descriptor")
			}
		})
	}
	for _, v6 := range []bool{false, true} {
		for _, group := range []bool{false, true} {
			t.Run(fmt.Sprintf("v6=%v/group=%v", v6, group), func(t *testing.T) {
				budget, _ := packetbudget.New(packetbudget.Config{MaxBytes: 1 << 20, ControlReserveBytes: 256 << 10, MaxCachedBytes: 65536, QueueEntries: 64})
				defer budget.Close()
				dev, err := CreateTUNWithOptions("sgrxtest", 1280, Options{DisableSegmentationOffloads: true, ReceiveGrouping: group, PacketBudget: budget})
				if err != nil {
					t.Fatal(err)
				}
				defer dev.Close()
				local, remote := "198.18.240.1", "198.18.240.2"
				network := "tcp4"
				prefix := local + "/24"
				family := "-4"
				if v6 {
					local, remote = "fd42:1234::1", "fd42:1234::2"
					network = "tcp6"
					prefix = local + "/64"
					family = "-6"
				}
				command := func(args ...string) {
					if out, e := exec.Command("ip", args...).CombinedOutput(); e != nil {
						t.Fatalf("ip %v: %s %v", args, out, e)
					}
				}
				if v6 {
					command(family, "addr", "add", prefix, "dev", "sgrxtest", "nodad")
				} else {
					command(family, "addr", "add", prefix, "dev", "sgrxtest")
				}
				command("link", "set", "sgrxtest", "up")
				if out, e := exec.Command("ethtool", "-k", "sgrxtest").CombinedOutput(); e != nil {
					t.Fatal(e)
				} else {
					t.Log(string(out))
				}
				listener, err := net.ListenTCP(network, &net.TCPAddr{IP: net.ParseIP(local)})
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
				listener.SetDeadline(time.Now().Add(15 * time.Second))
				want := make([]byte, 1200*12)
				for i := range want {
					want[i] = byte(i % 251)
				}
				done := make(chan error, 1)
				go func() {
					c, e := listener.AcceptTCP()
					if e != nil {
						done <- e
						return
					}
					defer c.Close()
					c.SetDeadline(time.Now().Add(15 * time.Second))
					got := make([]byte, len(want))
					_, e = io.ReadFull(c, got)
					if e == nil && !bytes.Equal(got, want) {
						e = fmt.Errorf("received payload mismatch")
					}
					if e == nil {
						_, e = c.Write(bytes.Repeat([]byte{0x5a}, len(want)))
					}
					done <- e
				}()
				src := netip.AddrPortFrom(netip.MustParseAddr(remote), 34567)
				dst := netip.AddrPortFrom(netip.MustParseAddr(local), uint16(listener.Addr().(*net.TCPAddr).Port))
				packet := func(flags header.TCPFlags, seq, ack uint32, data []byte) []byte {
					var p []byte
					iph, addr, addrlen := 20, 12, 4
					if v6 {
						p = tcp6Packet(src, dst, flags, uint32(len(data)), seq)
						iph, addr, addrlen = 40, 8, 16
					} else {
						p = tcp4Packet(src, dst, flags, uint32(len(data)), seq)
					}
					raw := p[offset:]
					binary.BigEndian.PutUint32(raw[iph+8:], ack)
					copy(raw[iph+20:], data)
					raw[iph+16], raw[iph+17] = 0, 0
					sum := pseudoHeaderChecksumNoFold(unix.IPPROTO_TCP, raw[addr:addr+addrlen], raw[addr+addrlen:addr+2*addrlen], uint16(len(raw)-iph))
					binary.BigEndian.PutUint16(raw[iph+16:], ^checksum(raw[iph:], sum))
					return bytes.Clone(p)
				}
				if _, e := dev.Write([][]byte{packet(header.TCPFlagSyn, 100, 0, nil)}, offset); e != nil {
					t.Fatal(e)
				}
				read := func() []byte {
					t.Helper()
					dev.File().SetReadDeadline(time.Now().Add(15 * time.Second))
					for {
						p := make([]byte, 2048)
						sz := []int{0}
						n, e := dev.Read([][]byte{p}, sz, 0)
						if e != nil {
							t.Fatal(e)
						}
						if n != 1 || sz[0] > 1280 {
							t.Fatal("unexpected outgoing segmentation", n, sz)
						}
						p = p[:sz[0]]
						if (!v6 && p[9] == 6) || (v6 && p[6] == 6) {
							iph := 20
							if v6 {
								iph = 40
							}
							if binary.BigEndian.Uint16(p[iph:]) == dst.Port() && binary.BigEndian.Uint16(p[iph+2:]) == src.Port() {
								return p
							}
						}
					}
				}
				synack := read()
				iph := 20
				if v6 {
					iph = 40
				}
				if synack[iph+13]&0x12 != 0x12 {
					t.Fatalf("not SYN ACK: %x", synack)
				}
				ack := binary.BigEndian.Uint32(synack[iph+4:]) + 1
				if _, e := dev.Write([][]byte{packet(header.TCPFlagAck, 101, ack, nil)}, offset); e != nil {
					t.Fatal(e)
				}
				pkts := make([][]byte, 12)
				for i := range pkts {
					pkts[i] = packet(header.TCPFlagAck, 101+uint32(i*1200), ack, want[i*1200:(i+1)*1200])
				}
				if _, e := dev.Write(pkts, offset); e != nil {
					t.Fatal(e)
				}
				received := 0
				for received < len(want) {
					p := read()
					hlen := int(p[iph+12]>>4) * 4
					data := p[iph+hlen:]
					if len(data) > 0 {
						if !bytes.Equal(data, bytes.Repeat([]byte{0x5a}, len(data))) {
							t.Fatal("outgoing payload mismatch")
						}
						if binary.BigEndian.Uint32(p[iph+4:]) != ack+uint32(received) {
							t.Fatal("outgoing TCP sequence mismatch")
						}
						received += len(data)
						if _, e := dev.Write([][]byte{packet(header.TCPFlagAck, 101+uint32(len(want)), ack+uint32(received), nil)}, offset); e != nil {
							t.Fatal(e)
						}
					}
				}
				if e := <-done; e != nil {
					t.Fatal(e)
				}
				if group {
					native := dev.(*NativeTun)
					if native.receiveGrouping == nil {
						t.Fatal("grouping inactive")
					}
				}
				t.Logf("received %d exact TCP bytes; returned %d bytes as ordinary MTU-sized packets", len(want), received)
			})
		}
	}
}
