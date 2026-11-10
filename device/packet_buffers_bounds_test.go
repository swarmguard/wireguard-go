/* SPDX-License-Identifier: MIT */

package device

import (
	"fmt"
	"io"
	"net/netip"
	"strings"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.zx2c4.com/wireguard/conn/bindtest"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/tuntest"
)

// TestSmallConstructorFailure rejects incompatible options without claiming
// the caller's TUN, bind or budget, or starting background workers.
func TestSmallConstructorFailure(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		size, mtu       int
		budget, capable bool
	}{
		{2048, 2017, true, true}, {2048, 0, true, true},
		{2048, 1280, true, false}, {2048, 1280, false, true},
		{-1, 1280, true, true}, {147, 1, true, true},
		{MaxMessageSize + 1, 1280, true, true},
	} {
		channel := tuntest.NewChannelTUN()
		plain := newSmallTestTUN(channel, tc.mtu)
		var tdev tun.Device = plain
		if !tc.capable {
			tdev = channel.TUN()
		}
		options := DeviceOptions{MessageBufferSize: tc.size}
		if tc.budget {
			options.PacketBudget = newTestBudget(t)
		}
		dev, err := NewDeviceWithOptions(tdev, bindtest.NewChannelBinds()[0], NewLogger(LogLevelSilent, ""), options)
		if err == nil {
			dev.Close()
			t.Fatalf("accepted incompatible options %+v", tc)
		}
		select {
		case <-plain.closed:
			t.Fatal("failed constructor closed caller's TUN")
		default:
		}
		if options.PacketBudget != nil {
			stats := options.PacketBudget.Snapshot()
			if stats.Outstanding != 0 || stats.Closed {
				t.Fatal("failed constructor claimed budget")
			}
			options.PacketBudget.Close()
		}
		plain.Close()
	}
}

// TestLegacyMessageBufferPool retains array-backed pooling without boxing a
// returned slice into the pool on the normal allocation path.
func TestLegacyMessageBufferPool(t *testing.T) {
	t.Parallel()
	dev := &Device{}
	dev.PopulatePools()
	buf := dev.GetMessageBuffer()
	if len(buf) != MaxMessageSize || cap(buf) != MaxMessageSize {
		t.Fatal("legacy capacity changed")
	}
	dev.PutMessageBuffer(buf)
	pooled := dev.pool.messageBuffers.Get()
	if _, ok := pooled.(*[MaxMessageSize]byte); !ok {
		t.Fatalf("legacy pool contains %T", pooled)
	}
	dev.pool.messageBuffers.Put(pooled)
}

// TestSmallControlBufferBounds rejects oversized control storage before touching
// the allocator, while retaining handshake and full-capacity control traffic.
func TestSmallControlBufferBounds(t *testing.T) {
	t.Parallel()
	budget := newTestBudget(t)
	defer budget.Close()
	dev := &Device{messageBufferSize: 2048, packetBudget: budget}
	before := budget.Snapshot()
	for _, size := range []int{-1, 0, 2049, MaxMessageSize} {
		if got := dev.controlBuffer(size); got != nil {
			t.Fatalf("allocated control buffer of size %d", size)
		}
	}
	if budget.Snapshot() != before {
		t.Fatal("rejected control allocation touched budget")
	}
	for _, size := range []int{MessageInitiationSize, MessageResponseSize, MessageCookieReplySize, 2048} {
		buf := dev.controlBuffer(size)
		if len(buf) != size || cap(buf) != size {
			t.Fatalf("control capacity: got %d/%d want %d", len(buf), cap(buf), size)
		}
		dev.releaseControlBuffer(buf)
	}
	if budget.Snapshot().Outstanding != 0 {
		t.Fatal("control allocation leaked")
	}
}

// TestSmallEncryptionBounds exercises the real encryption worker with tight
// capacities and an MTU racing queued data. Seal and padding must stay in place.
func TestSmallEncryptionBounds(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		size, payload, mtu int
		drop               bool
	}{
		{2048, 2016, 2016, false},
		{2048, 2015, 2016, false},
		{2048, 2017, 9000, true},
		{2047, 2015, 2015, false},
		{2047, 2015, 2016, true}, // Padding, rather than plaintext, exceeds capacity.
		{2048, 0, 2016, false},   // Keepalive still needs a tag.
	} {
		t.Run(fmt.Sprint(tc), func(t *testing.T) {
			dev := &Device{messageBufferSize: tc.size, log: NewLogger(LogLevelSilent, "")}
			dev.tun.mtu.Store(int32(tc.mtu))
			dev.queue.encryption = &outboundQueue{c: make(chan *QueueOutboundElementsContainer, 1)}
			aead, err := chacha20poly1305.New(make([]byte, chacha20poly1305.KeySize))
			if err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, tc.size)
			elem := &QueueOutboundElement{buffer: buf,
				packet:  buf[MessageTransportHeaderSize : MessageTransportHeaderSize+tc.payload],
				keypair: &Keypair{send: aead}}
			container := &QueueOutboundElementsContainer{elems: []*QueueOutboundElement{elem}}
			container.Lock()
			dev.queue.encryption.c <- container
			close(dev.queue.encryption.c)
			dev.RoutineEncryption(0)
			container.Lock() // The worker always releases the sequential consumer.
			defer container.Unlock()
			if tc.drop {
				if elem.packet != nil {
					t.Fatal("oversized encryption was not dropped")
				}
			} else if len(elem.packet) > tc.size || cap(elem.packet) != tc.size || &elem.packet[0] != &buf[0] {
				t.Fatal("encryption escaped owned backing storage")
			}
		})
	}
}

// mtuEventTUN supplies deterministic MTU events without starting I/O workers.
type mtuEventTUN struct {
	tun.Device
	mtu    int
	events chan tun.Event
}

func (d *mtuEventTUN) MTU() (int, error)        { return d.mtu, nil }
func (d *mtuEventTUN) Events() <-chan tun.Event { return d.events }

// TestSmallMTUUpdates verifies capping, reporting and recovery without growth.
func TestSmallMTUUpdates(t *testing.T) {
	t.Parallel()
	var errors []string
	dev := &Device{messageBufferSize: 2048, packetBudget: newTestBudget(t),
		log: &Logger{Verbosef: func(string, ...any) {}, Errorf: func(f string, args ...any) {
			errors = append(errors, fmt.Sprintf(f, args...))
		}}}
	defer dev.packetBudget.Close()
	dev.tun.mtu.Store(1280)
	for _, mtu := range []int{2016, 9000, 1280} {
		events := make(chan tun.Event, 1)
		events <- tun.EventMTUUpdate
		close(events)
		dev.tun.device = &mtuEventTUN{mtu: mtu, events: events}
		dev.RoutineTUNEventReader()
		if got := dev.tun.mtu.Load(); got != int32(min(mtu, 2016)) {
			t.Fatalf("MTU %d became %d", mtu, got)
		}
		buf := dev.GetMessageBuffer()
		if len(buf) != 2048 || cap(buf) != 2048 {
			t.Fatal("MTU grew storage")
		}
		dev.PutMessageBuffer(buf)
	}
	if len(errors) != 1 || !strings.Contains(errors[0], "capped") {
		t.Fatalf("missing visible limitation: %v", errors)
	}
}

// partialBorrowedTUN validates lifetimes even when writes compact and partially
// consume a batch, as packet-processing wrappers and native TUN errors can do.
type partialBorrowedTUN struct {
	tun.Device
	t      *testing.T
	owners []*budgetBorrowed
	calls  int
}

func (d *partialBorrowedTUN) BatchSize() int { return 4 }
func (d *partialBorrowedTUN) Write(bufs [][]byte, offset int) (int, error) {
	d.calls++
	for _, owner := range d.owners {
		if owner.releases != 0 {
			d.t.Fatal("owner released before synchronous write")
		}
	}
	if len(bufs) != 2 || len(bufs[0])-offset != 20 {
		d.t.Fatal("invalid packets not rejected")
	}
	if &bufs[0][0] != &d.owners[0].buf[0] {
		d.t.Fatal("borrowed write copied")
	}
	bufs[0], bufs[1] = bufs[1], bufs[0]
	return 1, io.ErrShortWrite
}

// TestSmallPartialWriteOwnership releases all original owners after a partial
// write, including packets rejected by source validation and malformed framing.
func TestSmallPartialWriteOwnership(t *testing.T) {
	t.Parallel()
	budget := newTestBudget(t)
	defer budget.Close()
	tdev := &partialBorrowedTUN{t: t}
	dev := &Device{packetBudget: budget, messageBufferSize: 2048,
		packetBuffers: tun.PacketBufferCapabilities{WriteUsesPacketLength: true}, log: NewLogger(LogLevelSilent, "")}
	dev.tun.device = tdev
	dev.net.bind = bindtest.NewChannelBinds()[0]
	dev.PopulatePools()
	peer := &Peer{device: dev}
	peer.queue.inbound = &autodrainingInboundQueue{c: make(chan *QueueInboundElementsContainer, 1)}
	peer.stopping.Add(1)
	dev.allowedips.Insert(netip.MustParsePrefix("10.0.0.1/32"), peer)
	container := dev.GetInboundElementsContainer()
	key := new(Keypair)
	for i := range 4 {
		owner := &budgetBorrowed{budget: budget, buf: budget.Get(2048, false)}
		tdev.owners = append(tdev.owners, owner)
		packet := owner.buf[16:36]
		packet[0], packet[3] = 0x45, 20
		copy(packet[12:16], []byte{10, 0, 0, 1})
		if i == 2 {
			packet[15] = 2
		} // Disallowed source.
		if i == 3 {
			packet[3] = 21
		} // Invalid length.
		elem := dev.GetInboundElement()
		elem.borrowedPacket, elem.packet, elem.keypair, elem.counter = owner, packet, key, uint64(i)
		container.elems = append(container.elems, elem)
	}
	peer.queue.inbound.c <- container
	close(peer.queue.inbound.c)
	peer.RoutineSequentialReceiver(4)
	if tdev.calls != 1 {
		t.Fatal("partial write not exercised")
	}
	for _, owner := range tdev.owners {
		if owner.releases != 1 {
			t.Fatalf("owner released %d times", owner.releases)
		}
	}
	if budget.Snapshot().Outstanding != 0 {
		t.Fatal("partial write leaked storage")
	}
}
