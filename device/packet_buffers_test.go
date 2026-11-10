/* SPDX-License-Identifier: MIT */

package device

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/conn/bindtest"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/tuntest"
)

// smallTestTUN consumes complete channel packets without silent truncation.
type smallTestTUN struct {
	tun.Device
	channel     *tuntest.ChannelTUN
	mtu         int
	closed      chan struct{}
	once        sync.Once
	failWrite   atomic.Bool
	partialRead atomic.Bool
	failed      chan struct{}
}

// newSmallTestTUN wraps a channel TUN with the plain native buffer contract.
func newSmallTestTUN(channel *tuntest.ChannelTUN, mtu int) *smallTestTUN {
	return &smallTestTUN{Device: channel.TUN(), channel: channel, mtu: mtu, closed: make(chan struct{}), failed: make(chan struct{}, 1)}
}

func (t *smallTestTUN) MTU() (int, error) { return t.mtu, nil }
func (t *smallTestTUN) PacketBufferCapabilities() tun.PacketBufferCapabilities {
	return tun.PacketBufferCapabilities{ReadConsumesWholePacket: true, WriteUsesPacketLength: true}
}
func (t *smallTestTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case <-t.closed:
		return 0, os.ErrClosed
	case p := <-t.channel.Outbound:
		if len(p) > len(bufs[0])-offset {
			return 0, io.ErrShortBuffer
		}
		sizes[0] = copy(bufs[0][offset:], p)
		if t.partialRead.Swap(false) {
			return 1, io.ErrShortBuffer
		}
		return 1, nil
	}
}
func (t *smallTestTUN) Close() error {
	t.once.Do(func() { close(t.closed); _ = t.Device.Close() })
	return nil
}

// TestSmallBufferValidation rejects unsupported TUNs and incompatible MTUs.
func TestSmallBufferValidation(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		size, mtu                  int
		budget, read, write, valid bool
	}{
		{2048, 1280, true, true, true, true}, {2048, 2016, true, true, true, true},
		{2048, 2017, true, true, true, false}, {2048, 0, true, true, true, false},
		{2048, 1280, false, true, true, false}, {2048, 1280, true, false, true, false},
		{2048, 1280, true, true, false, false}, {-1, 1280, true, true, true, false},
		{MaxMessageSize + 1, 1280, true, true, true, false},
	} {
		dev := &Device{messageBufferSize: tc.size, packetBuffers: tun.PacketBufferCapabilities{ReadConsumesWholePacket: tc.read, WriteUsesPacketLength: tc.write}}
		if tc.budget {
			dev.packetBudget = newTestBudget(t)
		}
		if err := dev.validatePacketBufferSize(tc.mtu); (err == nil) != tc.valid {
			t.Fatalf("%+v: %v", tc, err)
		}
	}
}

// TestSmallBufferBorrowedWrite preserves ownership and avoids scratch storage.
func TestSmallBufferBorrowedWrite(t *testing.T) {
	t.Parallel()
	for _, mode := range []struct{ plain, grows bool }{{false, false}, {true, false}, {true, true}} {
		plain := mode.plain && !mode.grows
		budget := newTestBudget(t)
		dev := &Device{packetBudget: budget, packetBuffers: tun.PacketBufferCapabilities{WriteUsesPacketLength: mode.plain, WriteMayGrowPacketStorage: mode.grows}}
		source := &budgetBorrowed{budget: budget, buf: budget.Get(2048, false)}
		copy(source.buf[16:], "plaintext")
		elem := &QueueInboundElement{borrowedPacket: source, packet: source.buf[16:25]}
		before := budget.Snapshot()
		var scratch [][]byte
		out := elem.tunWriteBuffer(dev, &scratch)
		if !bytes.Equal(out[16:], []byte("plaintext")) || source.releases != 0 {
			t.Fatal("bytes or lifetime changed")
		}
		if plain {
			if len(scratch) != 0 || &out[0] != &source.buf[0] || budget.Snapshot() != before {
				t.Fatal("plain write copied or allocated")
			}
		} else if len(scratch) != 1 || cap(out) != MaxMessageSize {
			t.Fatal("aggregation fallback lost")
		}
		for _, buffer := range scratch {
			dev.PutMessageBuffer(buffer)
		}
		elem.releasePacket(dev)
		if source.releases != 1 {
			t.Fatal("borrowed owner release count")
		}
		budget.Close()
		if budget.Snapshot().Outstanding != 0 {
			t.Fatal("leaked storage")
		}
	}
}

// TestSmallBufferTransfer exercises full encryption boundaries, oversized read
// recovery, both directions and interoperation with legacy-capacity storage.
func TestSmallBufferTransfer(t *testing.T) {
	for _, mtu := range []int{1280, 2016} {
		for _, otherSize := range []int{0, 2048} {
			t.Run(fmt.Sprintf("mtu%d/peer%d", mtu, otherSize), func(t *testing.T) {
				cfg, endpoints := genConfigs(t)
				binds := bindtest.NewChannelBinds()
				var devs [2]*Device
				var tunnels [2]*smallTestTUN
				var watched [2]*observedSmallBind
				var channels [2]*tuntest.ChannelTUN
				for i, size := range []int{2048, otherSize} {
					channels[i] = tuntest.NewChannelTUN()
					tunnels[i] = newSmallTestTUN(channels[i], mtu)
					watched[i] = &observedSmallBind{Bind: binds[i]}
					dev, err := NewDeviceWithOptions(tunnels[i], watched[i], NewLogger(LogLevelError, ""), DeviceOptions{PacketBudget: newTestBudget(t), MessageBufferSize: size})
					if err != nil {
						t.Fatal(err)
					}
					devs[i] = dev
					t.Cleanup(dev.Close)
					if err = dev.IpcSet(cfg[i] + fmt.Sprintf("allowed_ip=fd00::%d/128\n", 2-i)); err != nil {
						t.Fatal(err)
					}
					if err = dev.Up(); err != nil {
						t.Fatal(err)
					}
					endpoints[i^1] = fmt.Sprintf(endpoints[i^1], dev.net.port)
					buffer := dev.GetMessageBuffer()
					want := size
					if want == 0 {
						want = MaxMessageSize
					}
					if len(buffer) != want || cap(buffer) != want {
						t.Fatal("incorrect owned capacity")
					}
					dev.PutMessageBuffer(buffer)
				}
				for i, dev := range devs {
					if err := dev.IpcSet(endpoints[i]); err != nil {
						t.Fatal(err)
					}
				}
				// Two oversized packets must be consumed without closing the reader.
				for _, length := range []int{mtu + 1, 4096} {
					select {
					case channels[0].Outbound <- make([]byte, length):
					case <-time.After(3 * time.Second):
						t.Fatal("oversized read blocked")
					}
				}
				for _, source := range []int{0, 1} {
					if source == 1 && otherSize == 0 {
						// A legacy peer can send a transport packet above this
						// device's bound. It must be dropped and released once.
						packet := make([]byte, 4096)
						packet[0] = 0x45
						binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
						copy(packet[12:16], []byte{1, 0, 0, 2})
						copy(packet[16:20], []byte{1, 0, 0, 1})
						select {
						case channels[1].Outbound <- packet:
						case <-time.After(3 * time.Second):
							t.Fatal("legacy oversize send blocked")
						}
					}
					for _, version := range []int{4, 6} {
						for _, length := range []int{64, mtu - 15, mtu - 1, mtu} {
							p := make([]byte, length)
							for i := range p {
								p[i] = byte(i * 17)
							}
							if version == 4 {
								clear(p[:20])
								p[0] = 0x45
								p[9] = 1
								p[8] = 64
								binary.BigEndian.PutUint16(p[2:4], uint16(length))
								copy(p[12:16], []byte{1, 0, 0, byte(source + 1)})
								copy(p[16:20], []byte{1, 0, 0, byte(2 - source)})
							} else {
								clear(p[:40])
								p[0] = 0x60
								p[6] = 59
								p[7] = 64
								binary.BigEndian.PutUint16(p[4:6], uint16(length-40))
								p[8] = 0xfd
								p[23] = byte(source + 1)
								p[24] = 0xfd
								p[39] = byte(2 - source)
							}
							if source == 0 && version == 4 && length == 64 {
								tunnels[1].failWrite.Store(true)
								select {
								case channels[0].Outbound <- p:
								case <-time.After(3 * time.Second):
									t.Fatal("error test read blocked")
								}
								select {
								case <-tunnels[1].failed:
								case <-time.After(3 * time.Second):
									t.Fatal("missing failed write")
								}
							}
							if source == 0 && version == 6 && length == 64 {
								// A valid packet preceding an oversized read must
								// be sent before handling the partial-batch error.
								tunnels[source].partialRead.Store(true)
							}
							select {
							case channels[source].Outbound <- p:
							case <-time.After(3 * time.Second):
								t.Fatal("reader stopped")
							}
							select {
							case got := <-channels[source^1].Inbound:
								if !bytes.Equal(got, p) {
									t.Fatalf("v%d length%d changed", version, length)
								}
							case <-time.After(3 * time.Second):
								t.Fatal("transfer timeout")
							}
						}
					}
				}
				for _, dev := range devs {
					dev.Close()
					if dev.packetBudget.Snapshot().Outstanding != 0 {
						t.Fatal("shutdown leaked buffers")
					}
				}
				if otherSize == 0 && watched[0].oversized.Load() != 1 {
					t.Fatal("oversized borrowed receive not exercised")
				}
				for _, b := range watched {
					if b.received.Load() != b.released.Load() {
						t.Fatalf("borrowed ownership: received %d released %d", b.received.Load(), b.released.Load())
					}
				}
			})
		}
	}
}

// Write simulates a synchronous failed TUN write before the next valid packet.
func (t *smallTestTUN) Write(bufs [][]byte, offset int) (int, error) {
	if t.failWrite.Swap(false) {
		t.failed <- struct{}{}
		return 0, io.ErrShortWrite
	}
	return t.Device.Write(bufs, offset)
}

// observedSmallBind checks every received borrowed lease across error and close paths.
type observedSmallBind struct {
	conn.Bind
	received, released atomic.Int64
	oversized          atomic.Int64
}
type observedSmallPacket struct {
	conn.BorrowedPacket
	owner *observedSmallBind
	done  atomic.Bool
}

func (p *observedSmallPacket) Release() {
	if p.done.Swap(true) {
		panic("duplicate borrowed release")
	}
	p.BorrowedPacket.Release()
	p.owner.released.Add(1)
}
func (b *observedSmallBind) Open(port uint16) ([]conn.ReceiveBorrowedFunc, uint16, error) {
	fns, actual, err := b.Bind.Open(port)
	for i, receive := range fns {
		fns[i] = func(packets []conn.BorrowedPacket) (int, error) {
			n, err := receive(packets)
			for j := 0; j < n; j++ {
				if packets[j] != nil {
					if len(packets[j].Bytes()) > 2048 {
						b.oversized.Add(1)
					}
					packets[j] = &observedSmallPacket{BorrowedPacket: packets[j], owner: b}
					b.received.Add(1)
				}
			}
			return n, err
		}
	}
	return fns, actual, err
}

// TestSmallBufferPrivateGrowth rejects TUN storage outside the packet budget.
func TestSmallBufferPrivateGrowth(t *testing.T) {
	t.Parallel()
	budget := newTestBudget(t)
	defer budget.Close()
	dev := &Device{messageBufferSize: 2048, packetBudget: budget, packetBuffers: tun.PacketBufferCapabilities{
		ReadConsumesWholePacket: true, WriteUsesPacketLength: true, WriteMayGrowPacketStorage: true,
	}}
	if err := dev.validatePacketBufferSize(1280); err == nil {
		t.Fatal("small buffers allowed private TUN growth")
	}
}
