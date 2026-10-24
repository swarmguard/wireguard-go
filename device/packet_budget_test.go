// SPDX-License-Identifier: MIT
package device

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/conn/bindtest"
	"golang.zx2c4.com/wireguard/packetbudget"
	"golang.zx2c4.com/wireguard/tun/tuntest"
)

func newTestBudget(t testing.TB) *packetbudget.Budget {
	t.Helper()
	b, err := packetbudget.New(packetbudget.Config{MaxBytes: 2 << 20, ControlReserveBytes: 256 << 10, MaxCachedBytes: 128 << 10, QueueEntries: 16})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestBudgetPairedAdmission leaves neither queue with an orphan on rejection.
func TestBudgetPairedAdmission(t *testing.T) {
	budget := newTestBudget(t)
	dev := &Device{packetBudget: budget}
	dev.queue.encryption = &outboundQueue{c: make(chan *QueueOutboundElementsContainer, 16)}
	dev.queue.decryption = &inboundQueue{c: make(chan *QueueInboundElementsContainer, 16)}
	peer := &Peer{device: dev}
	peer.isRunning.Store(true)
	peer.queue.outbound = &autodrainingOutboundQueue{c: make(chan *QueueOutboundElementsContainer, 16)}
	peer.queue.inbound = &autodrainingInboundQueue{c: make(chan *QueueInboundElementsContainer, 16)}
	data := &QueueOutboundElementsContainer{elems: []*QueueOutboundElement{{packet: []byte{1}}}}
	control := &QueueOutboundElementsContainer{elems: []*QueueOutboundElement{{}}}
	for range 8 {
		if !dev.admitOutbound(peer, data) {
			t.Fatal("early data rejection")
		}
	}
	if dev.admitOutbound(peer, data) || len(peer.queue.outbound.c) != 8 || len(dev.queue.encryption.c) != 8 {
		t.Fatal("data reserve")
	}
	for range 8 {
		if !dev.admitOutbound(peer, control) {
			t.Fatal("control reserve inaccessible")
		}
	}
	<-peer.queue.outbound.c
	if dev.admitOutbound(peer, control) || len(peer.queue.outbound.c) != 15 {
		t.Fatal("partial publication")
	}
	in := new(QueueInboundElementsContainer)
	for range 8 {
		if !dev.admitInbound(peer, in, false) {
			t.Fatal("early inbound rejection")
		}
	}
	<-dev.queue.decryption.c
	if dev.admitInbound(peer, in, false) || len(dev.queue.decryption.c) != 7 {
		t.Fatal("inbound orphan")
	}
	if !dev.admitInbound(peer, in, true) {
		t.Fatal("inbound control reserve")
	}
	peer.isRunning.Store(false)
	if dev.admitInbound(peer, in, true) {
		t.Fatal("admission after stop")
	}
}

// TestBudgetDeviceTransferAndClose checks live encrypted traffic and complete
// ownership release over repeated activations with independent budgets.
func TestBudgetDeviceTransferAndClose(t *testing.T) {
	for range 3 {
		cfg, endpointCfg := genConfigs(t)
		binds := bindtest.NewChannelBinds()
		var pair testPair
		var budgets [2]*packetbudget.Budget
		for i := range pair {
			budgets[i] = newTestBudget(t)
			pair[i].tun = tuntest.NewChannelTUN()
			pair[i].ip = netip.AddrFrom4([4]byte{1, 0, 0, byte(i + 1)})
			dev, err := NewDeviceWithOptions(pair[i].tun.TUN(), binds[i], NewLogger(LogLevelError, ""), DeviceOptions{PacketBudget: budgets[i]})
			if err != nil {
				t.Fatal(err)
			}
			pair[i].dev = dev
			t.Cleanup(dev.Close)
			if err = dev.IpcSet(cfg[i]); err != nil {
				t.Fatal(err)
			}
			if err = dev.Up(); err != nil {
				t.Fatal(err)
			}
			endpointCfg[i^1] = fmt.Sprintf(endpointCfg[i^1], dev.net.port)
		}
		for i := range pair {
			if err := pair[i].dev.IpcSet(endpointCfg[i]); err != nil {
				t.Fatal(err)
			}
		}
		pair.Send(t, Ping, nil)
		pair.Send(t, Pong, nil)
		// Exhaust data capacity while leaving readers and the reserve available.
		fillers := make([][]byte, 2)
		for i, budget := range budgets {
			stats := budget.Snapshot()
			fillers[i] = budget.Get(budget.Config().MaxBytes-budget.Config().ControlReserveBytes-stats.DataBytes, false)
			if fillers[i] == nil {
				t.Fatal("failed to fill data capacity")
			}
		}
		var peers [2]*Peer
		for i := range pair {
			for _, peer := range pair[i].dev.peers.keyMap {
				peers[i] = peer
			}
		}

		// Rekeying must complete while data allocations are denied.
		previous := peers[0].keypairs.Current()
		peers[0].handshake.mutex.Lock()
		peers[0].handshake.lastSentHandshake = time.Time{}
		peers[0].handshake.mutex.Unlock()
		if err := peers[0].SendHandshakeInitiation(false); err != nil {
			t.Fatal(err)
		}
		rekeyDeadline := time.After(3 * time.Second)
		for peers[0].keypairs.Current() == previous {
			select {
			case <-rekeyDeadline:
				t.Fatal("rekey stalled under data saturation")
			case <-time.After(time.Millisecond):
			}
		}
		// Liveness packets use the reserve and are authenticated by the receiver.
		before := peers[1].rxBytes.Load()
		ok, err := peers[0].sendControlPacket(MessageLatencyProbeType, make([]byte, MessageLatencyTokenSize))
		if err != nil || !ok {
			t.Fatalf("control under saturation: %v %v", ok, err)
		}
		deadline := time.After(3 * time.Second)
		for peers[1].rxBytes.Load() == before {
			select {
			case <-deadline:
				t.Fatal("control made no progress")
			case <-time.After(time.Millisecond):
			}
		}
		for i, budget := range budgets {
			budget.Put(fillers[i])
		}
		pair.Send(t, Ping, nil)
		for i := range pair {
			pair[i].dev.Close()
		}
		for _, budget := range budgets {
			s := budget.Snapshot()
			if s.Outstanding != 0 || s.ManagedBytes != 0 || s.CachedBytes != 0 {
				t.Fatal(s)
			}
		}
	}
}

// TestBudgetConstructorFailure checks rollback before starting reader workers.
func TestBudgetConstructorFailure(t *testing.T) {
	budget, _ := packetbudget.New(packetbudget.Config{MaxBytes: 1024, ControlReserveBytes: 256, MaxCachedBytes: 512, QueueEntries: 16})
	tun := tuntest.NewChannelTUN()
	defer tun.TUN().Close()
	binds := bindtest.NewChannelBinds()
	dev, err := NewDeviceWithOptions(tun.TUN(), binds[0], NewLogger(LogLevelError, ""), DeviceOptions{PacketBudget: budget})
	if err == nil || dev != nil {
		t.Fatal("accepted impossible reader budget")
	}
	budget.Close()
	if s := budget.Snapshot(); s.Outstanding != 0 || s.ManagedBytes != 0 {
		t.Fatal(s)
	}
}

// budgetBorrowed is an external transport lease used to exercise TUN scratch.
type budgetBorrowed struct {
	budget   *packetbudget.Budget
	buf      []byte
	releases int
}

func (p *budgetBorrowed) Bytes() []byte           { return p.buf }
func (p *budgetBorrowed) Endpoint() conn.Endpoint { return nil }
func (p *budgetBorrowed) Release()                { p.releases++; p.budget.Put(p.buf); p.buf = nil }

// TestBudgetStagingAndWriteScratch covers independently stalled staged queues
// and refusal of receive-side copies without leaking borrowed ownership.
func TestBudgetStagingAndWriteScratch(t *testing.T) {
	budget := newTestBudget(t)
	tunnel := tuntest.NewChannelTUN()
	binds := bindtest.NewChannelBinds()
	dev, err := NewDeviceWithOptions(tunnel.TUN(), binds[0], NewLogger(LogLevelSilent, ""), DeviceOptions{PacketBudget: budget})
	if err != nil {
		t.Fatal(err)
	}
	defer dev.Close()
	peer := &Peer{device: dev}
	peer.isRunning.Store(true)
	peer.queue.staged = make(chan *QueueOutboundElementsContainer, 16)
	for range 9 {
		c := dev.GetOutboundElementsContainer()
		elem := dev.NewOutboundElement()
		if elem == nil {
			t.Fatal("unexpected buffer exhaustion")
		}
		elem.packet = elem.buffer[MessageTransportOffsetContent : MessageTransportOffsetContent+20]
		c.elems = append(c.elems, elem)
		peer.StagePackets(c)
	}
	if len(peer.queue.staged) != 8 || budget.Snapshot().QueueRejections != 1 {
		t.Fatal("staged data used reserve")
	}
	c := dev.GetOutboundElementsContainer()
	c.elems = append(c.elems, dev.newKeepaliveElement())
	peer.StagePackets(c)
	if len(peer.queue.staged) != 9 {
		t.Fatal("staged control rejected")
	}
	peer.FlushStagedPackets()
	source := &budgetBorrowed{budget: budget, buf: budget.Get(2048, false)}
	elem := &QueueInboundElement{borrowedPacket: source, packet: source.buf[16:36]}
	var scratch []*[MaxMessageSize]byte
	if elem.tunWriteBuffer(dev, &scratch) == nil || len(scratch) != 1 {
		t.Fatal("missing admitted copy")
	}
	for _, buf := range scratch {
		dev.PutMessageBuffer(buf)
	}
	scratch = nil
	filler := budget.Get(budget.Config().MaxBytes-budget.Config().ControlReserveBytes-budget.Snapshot().DataBytes, false)
	if filler == nil {
		t.Fatal("cannot fill data budget")
	}
	// A cached message buffer is already charged, so fill it too if reused.
	var held []*[MaxMessageSize]byte
	for {
		buf := dev.GetMessageBuffer()
		if buf == nil {
			break
		}
		held = append(held, buf)
	}
	if elem.tunWriteBuffer(dev, &scratch) != nil || len(scratch) != 0 {
		t.Fatal("unbudgeted TUN scratch")
	}
	elem.releasePacket(dev)
	if source.releases != 1 {
		t.Fatal("borrowed lease not released once")
	}
	budget.Put(filler)
	for _, buf := range held {
		dev.PutMessageBuffer(buf)
	}
	dev.Close()
	if s := budget.Snapshot(); s.ManagedBytes != 0 || s.Outstanding != 0 {
		t.Fatal(s)
	}
}
