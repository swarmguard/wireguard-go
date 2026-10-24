/* SPDX-License-Identifier: MIT */

package tun

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestNativeRealCompactTUN verifies kernel segmentation, complete checksums,
// reinjection, MTU and events for all constructor/descriptor variants.
// It requires CAP_NET_ADMIN and creates temporary test interfaces only.
func TestNativeRealCompactTUN(t *testing.T) {
	for _, kind := range []string{"named", "file-framed", "file-plain", "fd-framed", "fd-plain"} {
		t.Run(kind, func(t *testing.T) {
			dev := realCompactTUN(t, kind)
			native := dev.(*NativeTun)
			if dev.BatchSize() != 1 || !native.disableOffloads || native.tcpGROTable != nil || native.udpGROTable != nil || native.toWrite != nil {
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
			// Kernel segmentation must turn a nine-segment send into nine plain reads.
			if err := raw.Control(func(fd uintptr) { optionErr = unix.SetsockoptInt(int(fd), unix.SOL_UDP, unix.UDP_SEGMENT, 100) }); err != nil {
				t.Fatal(err)
			}
			if optionErr != nil {
				t.Fatalf("UDP segmentation check unavailable: %v", optionErr)
			}
			payload := make([]byte, 900)
			for i := range payload {
				payload[i] = byte(i*37 + 11)
			}
			if _, err := udp.WriteToUDP(payload, &net.UDPAddr{IP: net.IPv4(198, 18, 0, 2), Port: 9000}); err != nil {
				t.Fatal(err)
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
	options := Options{DisableOffloads: true}
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
		// Prove adoption clears offloads previously enabled on the descriptor.
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
	return dev
}

func skipUnavailableTUN(t *testing.T, err error) {
	t.Helper()
	if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) || errors.Is(err, os.ErrNotExist) {
		t.Skipf("real TUN unavailable: %v", err)
	}
}
