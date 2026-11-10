/* SPDX-License-Identifier: MIT */

package tun

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestNativeRealCompactTUN verifies kernel segmentation, complete checksums,
// reinjection, MTU and events for all constructor/descriptor variants.
// It requires CAP_NET_ADMIN and creates temporary test interfaces only.
func TestNativeRealCompactTUN(t *testing.T) {
	testNativeRealCompactTUN(t, true)
}

// TestNativeRealCompactTUNPlainUDP checks ordinary UDP independently of explicit
// UDP_SEGMENT support, which requires checksum offloads on some older kernels.
func TestNativeRealCompactTUNPlainUDP(t *testing.T) {
	testNativeRealCompactTUN(t, false)
}

// testNativeRealCompactTUN exercises both the ordinary and segmented send paths.
func testNativeRealCompactTUN(t *testing.T, segmented bool) {
	for _, kind := range []string{"named", "file-framed", "file-plain", "fd-framed", "fd-plain"} {
		t.Run(kind, func(t *testing.T) {
			dev := realCompactTUN(t, kind)
			native := dev.(*NativeTun)
			if dev.BatchSize() != 1 || !native.noSegmentation || native.tcpGROTable != nil || native.udpGROTable != nil || native.toWrite != nil {
				t.Fatal("compact setup")
			}
			if mtu, err := dev.MTU(); mtu != 1280 || err != nil {
				t.Fatal(mtu, err)
			}
			name, err := dev.Name()
			if err != nil {
				t.Fatal(err)
			}
			sock, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer unix.Close(sock)
			for _, item := range []struct {
				request uint
				address []byte
			}{
				{unix.SIOCSIFADDR, []byte{198, 18, 0, 1}},
				{unix.SIOCSIFNETMASK, []byte{255, 255, 255, 252}},
			} {
				ifr, _ := unix.NewIfreq(name)
				if err := ifr.SetInet4Addr(item.address); err != nil {
					t.Fatal(err)
				}
				if err := unix.IoctlIfreq(sock, item.request, ifr); err != nil {
					t.Fatal(err)
				}
			}
			setUp := func(up bool) {
				ifr, _ := unix.NewIfreq(name)
				if err := unix.IoctlIfreq(sock, unix.SIOCGIFFLAGS, ifr); err != nil {
					t.Fatal(err)
				}
				flags := ifr.Uint16()
				if up {
					flags |= unix.IFF_UP
				} else {
					flags &^= unix.IFF_UP
				}
				ifr.SetUint16(flags)
				if err := unix.IoctlIfreq(sock, unix.SIOCSIFFLAGS, ifr); err != nil {
					t.Fatal(err)
				}
			}
			waitEvent := func(want Event) {
				timer := time.NewTimer(3 * time.Second)
				defer timer.Stop()
				for {
					select {
					case e := <-dev.Events():
						if e&want != 0 {
							return
						}
					case <-timer.C:
						t.Fatalf("missing event %v", want)
					}
				}
			}
			monitored := !strings.HasPrefix(kind, "fd-")
			setUp(true)
			if monitored {
				waitEvent(EventUp)
			}
			udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(198, 18, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer udp.Close()
			raw, err := udp.SyscallConn()
			if err != nil {
				t.Fatal(err)
			}
			var optionErr error
			if err := raw.Control(func(fd uintptr) {
				optionErr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, name)
			}); err != nil {
				t.Fatal(err)
			}
			if optionErr != nil {
				t.Fatal(optionErr)
			}
			// Keep explicit UDP segmentation separate from ordinary socket sends.
			if segmented {
				if err := raw.Control(func(fd uintptr) { optionErr = unix.SetsockoptInt(int(fd), unix.SOL_UDP, unix.UDP_SEGMENT, 100) }); err != nil {
					t.Fatal(err)
				}
				if optionErr != nil {
					t.Fatalf("UDP segmentation check unavailable: %v", optionErr)
				}
			}
			payload := make([]byte, 900)
			for i := range payload {
				payload[i] = byte(i*37 + 11)
			}
			sendSize := 100
			if segmented {
				sendSize = len(payload)
			}
			for start := 0; start < len(payload); start += sendSize {
				if _, err := udp.WriteToUDP(payload[start:start+sendSize], &net.UDPAddr{IP: net.IPv4(198, 18, 0, 2), Port: 9000}); err != nil {
					t.Fatal(err)
				}
			}
			if err := dev.File().SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			bufs, sizes := batchBuffers(128)
			for i := 0; i < 9; i++ {
				var p []byte
				for {
					n, err := dev.Read(bufs, sizes, 16)
					if n != 1 || err != nil {
						t.Fatal(n, err)
					}
					p = bufs[0][16 : 16+sizes[0]]
					// Interface activation may also emit IPv6 neighbour discovery.
					// The read deadline still bounds waiting for our test flow.
					if len(p) >= 28 && p[0] == 0x45 && p[9] == unix.IPPROTO_UDP &&
						binary.BigEndian.Uint16(p[22:]) == 9000 {
						break
					}
				}
				if len(p) != 128 || p[0] != 0x45 || p[9] != unix.IPPROTO_UDP || !bytes.Equal(p[28:], payload[i*100:(i+1)*100]) {
					t.Fatal("kernel segmentation/order")
				}
				pseudo := pseudoHeaderChecksumNoFold(unix.IPPROTO_UDP, p[12:16], p[16:20], 108)
				if checksum(p[:20], 0) != 0xffff || checksum(p[20:], pseudo) != 0xffff {
					t.Fatal("kernel checksum")
				}
				// Reverse the packet and inject it back into the kernel socket.
				src := bytes.Clone(p[12:16])
				copy(p[12:16], p[16:20])
				copy(p[16:20], src)
				port := binary.BigEndian.Uint16(p[20:])
				binary.BigEndian.PutUint16(p[20:], 9000)
				binary.BigEndian.PutUint16(p[22:], port)
				clear(p[10:12])
				binary.BigEndian.PutUint16(p[10:], ^checksum(p[:20], 0))
				clear(p[26:28])
				pseudo = pseudoHeaderChecksumNoFold(unix.IPPROTO_UDP, p[12:16], p[16:20], 108)
				binary.BigEndian.PutUint16(p[26:], ^checksum(p[20:], pseudo))
				if _, err := dev.Write([][]byte{bufs[0][:16+sizes[0]]}, 16); err != nil {
					t.Fatal(err)
				}
				if err := udp.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
					t.Fatal(err)
				}
				got := make([]byte, 200)
				n, _, err := udp.ReadFromUDP(got)
				if err != nil || !bytes.Equal(got[:n], payload[i*100:(i+1)*100]) {
					t.Fatal("kernel return packet", err)
				}
			}
			t.Log("packet checks passed")
			setUp(false)
			if monitored {
				waitEvent(EventDown)
			}
		})
	}
}

// realCompactTUN creates a named TUN or adopts a descriptor with optional framing.
func realCompactTUN(t *testing.T, kind string) Device {
	t.Helper()
	options := Options{DisableSegmentationOffloads: true}
	var dev Device
	var err error
	if kind == "named" {
		dev, err = CreateTUNWithOptions("sgcmp%d", 1280, options)
	} else {
		fd, openErr := unix.Open(cloneDevicePath, unix.O_RDWR|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
		if openErr != nil {
			skipUnavailableTUN(t, openErr)
			t.Fatal(openErr)
		}
		ifr, _ := unix.NewIfreq("sgcmp%d")
		framed := strings.HasSuffix(kind, "-framed")
		flags := uint16(unix.IFF_TUN | unix.IFF_NO_PI)
		if framed {
			flags |= unix.IFF_VNET_HDR
		}
		ifr.SetUint16(flags)
		if err = unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
			unix.Close(fd)
			skipUnavailableTUN(t, err)
			t.Fatal(err)
		}
		// Prove adoption clears segmentation offloads previously enabled on the descriptor.
		if framed {
			if err = unix.IoctlSetInt(fd, unix.TUNSETOFFLOAD, tunTCPOffloads); err != nil {
				unix.Close(fd)
				t.Fatal(err)
			}
		}
		if strings.HasPrefix(kind, "file-") {
			dev, err = CreateTUNFromFileWithOptions(os.NewFile(uintptr(fd), "tun"), 1280, options)
		} else {
			dev, _, err = CreateUnmonitoredTUNFromFDWithOptions(fd, options)
			if err == nil {
				err = dev.(*NativeTun).setMTU(1280)
			}
		}
	}
	if err != nil {
		if dev != nil {
			dev.Close()
		}
		skipUnavailableTUN(t, err)
		t.Fatal(err)
	}
	t.Cleanup(func() { dev.Close() })
	if dev.(*NativeTun).vnetHdr {
		raw, err := dev.File().SyscallConn()
		if err != nil {
			t.Fatal(err)
		}
		var order, size int
		var ioctlErr error
		if err := raw.Control(func(fd uintptr) {
			order, ioctlErr = unix.IoctlGetInt(int(fd), unix.TUNGETVNETLE)
			if ioctlErr == nil {
				size, ioctlErr = unix.IoctlGetInt(int(fd), unix.TUNGETVNETHDRSZ)
			}
		}); err != nil || ioctlErr != nil || order != 1 || size != 10 {
			t.Fatal("compact framing", order, size, err, ioctlErr)
		}
	}
	return dev
}

func skipUnavailableTUN(t *testing.T, err error) {
	t.Helper()
	if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) || errors.Is(err, os.ErrNotExist) {
		t.Skipf("real TUN unavailable: %v", err)
	}
}

// TestNativeRealCompactIPv6 checks IPv6 UDP segmentation through a real TUN.
func TestNativeRealCompactIPv6(t *testing.T) {
	for _, mtu := range []int{1280, 1420} {
		for _, kind := range []string{"named", "file-framed", "fd-framed"} {
			t.Run(fmt.Sprintf("%d/%s", mtu, kind), func(t *testing.T) {
				dev := realCompactTUN(t, kind)
				if err := dev.(*NativeTun).setMTU(mtu); err != nil {
					t.Fatal(err)
				}
				name, err := dev.Name()
				if err != nil {
					t.Fatal(err)
				}
				for _, args := range [][]string{{"-6", "addr", "add", "fd00:2585::1/64", "dev", name, "nodad"}, {"link", "set", name, "up"}} {
					if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
						t.Fatalf("ip: %s %v", out, err)
					}
				}
				// Drain interface notifications without depending on the known down-event bug.
				done := make(chan struct{})
				defer close(done)
				go func() {
					for {
						select {
						case _, ok := <-dev.Events():
							if !ok {
								return
							}
						case <-done:
							return
						}
					}
				}()
				udp, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.ParseIP("fd00:2585::1")})
				if err != nil {
					t.Fatal(err)
				}
				defer udp.Close()
				raw, err := udp.SyscallConn()
				if err != nil {
					t.Fatal(err)
				}
				var optionErr error
				if err := raw.Control(func(fd uintptr) { optionErr = unix.SetsockoptInt(int(fd), unix.SOL_UDP, unix.UDP_SEGMENT, 101) }); err != nil || optionErr != nil {
					t.Fatal(err, optionErr)
				}
				payload := make([]byte, 845)
				for i := range payload {
					payload[i] = byte(i*37 + 11)
				}
				if _, err := udp.WriteToUDP(payload, &net.UDPAddr{IP: net.ParseIP("fd00:2585::2"), Port: 9000}); err != nil {
					t.Fatal(err)
				}
				if err := dev.File().SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
					t.Fatal(err)
				}
				bufs, sizes := batchBuffers(8)
				for pos := 0; pos < len(payload); {
					n, err := dev.Read(bufs, sizes, 16)
					if err != nil || n != 1 {
						t.Fatal(n, err)
					}
					p := bufs[0][16 : 16+sizes[0]]
					if len(p) < 48 || p[0]>>4 != 6 || p[6] != unix.IPPROTO_UDP || binary.BigEndian.Uint16(p[42:]) != 9000 {
						continue
					}
					length := 101
					if length > len(payload)-pos {
						length = len(payload) - pos
					}
					if len(p) != 48+length || !bytes.Equal(p[48:], payload[pos:pos+length]) {
						t.Fatal("segmentation or order")
					}
					pseudo := pseudoHeaderChecksumNoFold(unix.IPPROTO_UDP, p[8:24], p[24:40], uint16(len(p)-40))
					if checksum(p[40:], pseudo) != 0xffff {
						t.Fatal("IPv6 checksum")
					}
					src := bytes.Clone(p[8:24])
					copy(p[8:24], p[24:40])
					copy(p[24:40], src)
					port := binary.BigEndian.Uint16(p[40:])
					binary.BigEndian.PutUint16(p[40:], 9000)
					binary.BigEndian.PutUint16(p[42:], port)
					clear(p[46:48])
					pseudo = pseudoHeaderChecksumNoFold(unix.IPPROTO_UDP, p[8:24], p[24:40], uint16(len(p)-40))
					binary.BigEndian.PutUint16(p[46:], ^checksum(p[40:], pseudo))
					if _, err := dev.Write([][]byte{bufs[0][:16+sizes[0]]}, 16); err != nil {
						t.Fatal(err)
					}
					if err := udp.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
						t.Fatal(err)
					}
					got := make([]byte, 200)
					n, _, err = udp.ReadFromUDP(got)
					if err != nil || !bytes.Equal(got[:n], payload[pos:pos+length]) {
						t.Fatal("IPv6 reinjection", err)
					}
					pos += length
				}
			})
		}
	}
}
