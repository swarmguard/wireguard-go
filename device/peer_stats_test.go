/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 SwarmGuard. All Rights Reserved.
 */

package device

import (
	"fmt"
	"runtime"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn/bindtest"
	"golang.zx2c4.com/wireguard/tun/tuntest"
)

// TestPeerStats verifies exact values, zero handshake semantics, and independent copies.
func TestPeerStats(t *testing.T) {
	t.Parallel()
	dev := &Device{}
	if got := dev.PeerStats(); len(got) != 0 {
		t.Fatalf("empty device returned %v", got)
	}
	dev.peers.keyMap = make(map[NoisePublicKey]*Peer)
	want := make(map[NoisePublicKey]PeerStats)
	for index, nano := range []int64{0, 1700000000 * int64(time.Second), 1700000000123456789} {
		key := NoisePublicKey{byte(index + 1)}
		peer := &Peer{}
		peer.rxBytes.Store(uint64(1)<<63 + uint64(index))
		peer.txBytes.Store(uint64(index + 100))
		peer.lastHandshakeNano.Store(nano)
		dev.peers.keyMap[key] = peer
		entry := PeerStats{PublicKey: key, RxBytes: peer.rxBytes.Load(), TxBytes: peer.txBytes.Load()}
		if nano != 0 {
			entry.LastHandshake = time.Unix(0, nano).UTC()
		}
		want[key] = entry
	}
	got := dev.PeerStats()
	if len(got) != len(want) {
		t.Fatalf("got %d peers, want %d", len(got), len(want))
	}
	for _, entry := range got {
		if entry != want[entry.PublicKey] {
			t.Fatalf("unexpected statistics: %+v", entry)
		}
	}

	// Changing returned values must not change the device or later results.
	original := got[0]
	got[0] = PeerStats{}
	for _, entry := range dev.PeerStats() {
		if entry != want[entry.PublicKey] {
			t.Fatalf("returned data aliases the device: %+v", entry)
		}
	}

	// Later atomic updates must not change an earlier reading.
	peer := dev.peers.keyMap[original.PublicKey]
	peer.rxBytes.Add(1)
	peer.txBytes.Add(2)
	peer.lastHandshakeNano.Store(1)
	if original != want[original.PublicKey] {
		t.Fatal("earlier reading changed")
	}
	for _, entry := range dev.PeerStats() {
		if entry.PublicKey == original.PublicKey && (entry.RxBytes != original.RxBytes+1 || entry.TxBytes != original.TxBytes+2 || entry.LastHandshake != time.Unix(0, 1).UTC()) {
			t.Fatalf("later reading did not reflect updates: %+v", entry)
		}
	}
}

// TestPeerStatsConcurrentLifecycle reads while counters, membership, and device lifetime change.
func TestPeerStatsConcurrentLifecycle(t *testing.T) {
	t.Parallel()
	dev := NewDevice(tuntest.NewChannelTUN().TUN(), bindtest.NewChannelBinds()[0], NewLogger(LogLevelSilent, ""))
	t.Cleanup(dev.Close)
	stableKey := (&NoisePrivateKey{8}).publicKey()
	peer, err := dev.NewPeer(stableKey)
	if err != nil {
		t.Fatal(err)
	}

	stop := make(chan struct{})
	var workers sync.WaitGroup
	workers.Add(2)
	readerReady := make(chan struct{})
	go func() {
		defer workers.Done()
		dev.PeerStats()
		close(readerReady)
		for {
			select {
			case <-stop:
				return
			default:
				dev.PeerStats()
				runtime.Gosched()
			}
		}
	}()
	go func() {
		defer workers.Done()
		for {
			select {
			case <-stop:
				return
			default:
				peer.rxBytes.Add(1)
				peer.txBytes.Add(2)
				peer.lastHandshakeNano.Store(time.Now().UnixNano())
				runtime.Gosched()
			}
		}
	}()
	<-readerReady

	finished := make(chan error, 1)
	go func() {
		var operationErr error
		key := (&NoisePrivateKey{16}).publicKey()
		for range 100 {
			if _, operationErr = dev.NewPeer(key); operationErr != nil {
				break
			}
			dev.RemovePeer(key)
		}
		dev.Close()
		close(stop)
		workers.Wait()
		finished <- operationErr
	}()
	select {
	case err := <-finished:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("statistics collection blocked peer lifecycle or close")
	}
	if got := dev.PeerStats(); len(got) != 0 {
		t.Fatalf("closed device returned %v", got)
	}
}

// BenchmarkPeerStats compares typed copying with UAPI text serialization only.
// Socket transport and wgctrl parsing costs are not included in the baseline.
func BenchmarkPeerStats(b *testing.B) {
	for _, count := range []int{1, 16} {
		dev := &Device{}
		dev.peers.keyMap = make(map[NoisePublicKey]*Peer, count)
		for index := range count {
			key := NoisePublicKey{byte(index + 1)}
			peer := &Peer{}
			peer.handshake.remoteStatic = key
			peer.rxBytes.Store(12345)
			peer.txBytes.Store(67890)
			peer.lastHandshakeNano.Store(1700000000123456789)
			dev.peers.keyMap[key] = peer
		}
		b.Run(fmt.Sprintf("%d/typed", count), func(b *testing.B) {
			b.ReportAllocs()
			for n := 0; n < b.N; n++ {
				if len(dev.PeerStats()) != count {
					b.Fatal("missing peers")
				}
			}
		})
		b.Run(fmt.Sprintf("%d/uapi", count), func(b *testing.B) {
			b.ReportAllocs()
			for n := 0; n < b.N; n++ {
				if _, err := dev.IpcGet(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
