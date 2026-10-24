/* SPDX-License-Identifier: MIT */

package device

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/conn/bindtest"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/tuntest"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// capacityTUN signals when the device has allocated its TUN read buffers.
type capacityTUN struct {
	tun.Device
	capacity int
	ready    chan struct{}
	once     sync.Once
}

func (t *capacityTUN) BatchSize() int { return t.capacity }
func (t *capacityTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	t.once.Do(func() { close(t.ready) })
	return t.Device.Read(bufs, sizes, offset)
}

type capacityBind struct {
	conn.Bind
	capacity int
}

func (b *capacityBind) BatchSize() int { return b.capacity }

// fixtureCapacity selects the measurement preset without changing production globals.
func fixtureCapacity(tb testing.TB) int {
	tb.Helper()
	value := os.Getenv("SG_BENCH_BATCH")
	if value == "" {
		return 128
	}
	n, err := strconv.Atoi(value)
	if err != nil || (n != 8 && n != 128) {
		tb.Fatal("invalid SG_BENCH_BATCH", value)
	}
	return n
}

// nativeFixtureCapacity models the plain compact TUN while the bind retains
// an eight-packet effective WireGuard batch.
func nativeFixtureCapacity(capacity int) int {
	if capacity == 8 {
		return 1
	}
	return capacity
}

func newCapacityDevice(tb testing.TB, capacity, peers int) *Device {
	tb.Helper()
	channel := tuntest.NewChannelTUN()
	tunnel := &capacityTUN{Device: channel.TUN(), capacity: nativeFixtureCapacity(capacity), ready: make(chan struct{})}
	binds := bindtest.NewChannelBinds()
	dev := NewDevice(tunnel, &capacityBind{Bind: binds[0], capacity: capacity}, NewLogger(LogLevelSilent, ""))
	var private NoisePrivateKey
	private[0], private[1] = 111, 17
	if err := dev.IpcSet("private_key=" + hex.EncodeToString(private[:]) + "\n"); err != nil {
		dev.Close()
		tb.Fatal(err)
	}
	for i := 0; i < peers; i++ {
		var key NoisePrivateKey
		key[0], key[1] = byte(i+1), byte(i+7)
		pub := key.publicKey()
		if _, err := dev.NewPeer(pub); err != nil {
			dev.Close()
			tb.Fatal(err)
		}
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		tb.Fatal(err)
	}
	select {
	case <-tunnel.ready:
	case <-time.After(3 * time.Second):
		dev.Close()
		tb.Fatal("TUN reader did not start")
	}
	return dev
}

// BenchmarkBatchDeviceCreate measures complete device allocation and shutdown.
func BenchmarkBatchDeviceCreate(b *testing.B) {
	capacity := fixtureCapacity(b)
	for _, peers := range []int{0, 1, 16} {
		b.Run(fmt.Sprintf("peers%d", peers), func(b *testing.B) {
			warm := newCapacityDevice(b, capacity, peers)
			warm.Close()
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				dev := newCapacityDevice(b, capacity, peers)
				dev.Close()
			}
		})
	}
}

// TestBatchRetainedHeap reports live heap over repeated complete lifecycles.
func TestBatchRetainedHeap(t *testing.T) {
	if os.Getenv("SG_BATCH_MEASURE") != "1" {
		t.Skip("opt-in heap measurement")
	}
	capacity := fixtureCapacity(t)
	for _, peers := range []int{0, 1, 16} {
		warm := newCapacityDevice(t, capacity, peers)
		warm.Close()
		var before, live, after runtime.MemStats
		runtime.GC()
		runtime.GC()
		runtime.ReadMemStats(&before)
		for cycle := 0; cycle < 10; cycle++ {
			dev := newCapacityDevice(t, capacity, peers)
			runtime.GC()
			runtime.GC()
			runtime.ReadMemStats(&live)
			runtime.KeepAlive(dev)
			dev.Close()
			runtime.GC()
			runtime.GC()
			runtime.ReadMemStats(&after)
			t.Logf("batch=%d peers=%d cycle=%d before=%d live=%d closed=%d goroutines=%d", capacity, peers, cycle, before.HeapAlloc, live.HeapAlloc, after.HeapAlloc, runtime.NumGoroutine())
		}
	}
}

func capacityPair(tb testing.TB, capacity int) (pair testPair) {
	tb.Helper()
	tb.Cleanup(func() { closeCapacityPair(pair) })
	configs, endpoints := genConfigs(tb)
	binds := bindtest.NewChannelBinds()
	for i := range pair {
		p := &pair[i]
		p.tun = tuntest.NewChannelTUN()
		p.ip = netip.AddrFrom4([4]byte{1, 0, 0, byte(i + 1)})
		tunnel := &capacityTUN{Device: p.tun.TUN(), capacity: nativeFixtureCapacity(capacity), ready: make(chan struct{})}
		p.dev = NewDevice(tunnel, &capacityBind{Bind: binds[i], capacity: capacity}, NewLogger(LogLevelSilent, ""))
		if err := p.dev.IpcSet(configs[i]); err != nil {
			tb.Fatal(err)
		}
		if err := p.dev.Up(); err != nil {
			tb.Fatal(err)
		}
		endpoints[i^1] = fmt.Sprintf(endpoints[i^1], p.dev.net.port)
	}
	for i := range pair {
		if err := pair[i].dev.IpcSet(endpoints[i]); err != nil {
			tb.Fatal(err)
		}
	}
	return pair
}

// TestBatchDeviceTransfer checks encryption, integrity and lifecycle at both capacities.
func TestBatchDeviceTransfer(t *testing.T) {
	for _, capacity := range []int{8, 128} {
		t.Run(fmt.Sprint(capacity), func(t *testing.T) {
			for cycle := 0; cycle < 10; cycle++ {
				pair := capacityPair(t, capacity)
				for _, p := range pair {
					if p.dev.BatchSize() != capacity {
						t.Fatal("effective batch differs")
					}
				}
				pair.Send(t, Ping, nil)
				pair.Send(t, Pong, nil)
				closeCapacityPair(pair)
			}
		})
	}
}

// BenchmarkBatchEncryptedTransfer measures an established bidirectional local
// tunnel, not an agent ICE or relay path. One operation is one delivered packet.
func BenchmarkBatchEncryptedTransfer(b *testing.B) {
	pair := capacityPair(b, fixtureCapacity(b))
	pair.Send(b, Ping, nil)
	pair.Send(b, Pong, nil)
	for _, size := range []int{64, 512, 1280} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			packet := tuntest.Ping(pair[0].ip, pair[1].ip)
			if len(packet) < size {
				packet = append(packet, make([]byte, size-len(packet))...)
			}
			// Correct the IP length; WireGuard treats the inner payload as opaque.
			packet[2], packet[3] = byte(size>>8), byte(size)
			ip := header.IPv4(packet)
			ip.SetChecksum(0)
			ip.SetChecksum(^ip.CalculateChecksum())
			b.ReportAllocs()
			b.SetBytes(int64(len(packet)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				pair[1].tun.Outbound <- packet
				got := <-pair[0].tun.Inbound
				if !bytes.Equal(got, packet) {
					b.Fatal("packet changed")
				}
			}
		})
	}
}

// measureTrafficCycle returns heap observations after its two-device fixture
// has gone out of scope, so the following GC can collect closed devices.
func measureTrafficCycle(t *testing.T, capacity int) (idle, active uint64) {
	pair := capacityPair(t, capacity)
	pair.Send(t, Ping, nil)
	pair.Send(t, Pong, nil)
	var stats runtime.MemStats
	runtime.GC()
	runtime.GC()
	runtime.ReadMemStats(&stats)
	idle = stats.HeapAlloc
	for i := 0; i < 1000; i++ {
		pair.Send(t, SendDirection(i%2 == 0), nil)
	}
	runtime.GC()
	runtime.GC()
	runtime.ReadMemStats(&stats)
	active = stats.HeapAlloc
	closeCapacityPair(pair)
	runtime.KeepAlive(pair)
	return idle, active
}

// TestBatchTrafficHeap reports after-traffic retention and completed cycles.
func TestBatchTrafficHeap(t *testing.T) {
	if os.Getenv("SG_BATCH_MEASURE") != "1" {
		t.Skip("opt-in heap measurement")
	}
	capacity := fixtureCapacity(t)
	for cycle := 0; cycle < 100; cycle++ {
		// Subtest cleanup releases the registered device closures before measuring
		// closed-state heap in the parent; otherwise the test itself retains them.
		var idle, active uint64
		t.Run(fmt.Sprint(cycle), func(t *testing.T) { idle, active = measureTrafficCycle(t, capacity) })
		var stats runtime.MemStats
		runtime.GC()
		runtime.GC()
		runtime.ReadMemStats(&stats)
		t.Logf("batch=%d cycle=%d idle=%d traffic=%d closed=%d goroutines=%d", capacity, cycle, idle, active, stats.HeapAlloc, runtime.NumGoroutine())
	}
}

// closeCapacityPair consumes notifications as the agent does. Unconsumed peer
// events retain peers and their finalizer-owned queues even after device close.
func closeCapacityPair(pair testPair) {
	for _, p := range pair {
		if p.dev != nil {
			p.dev.Close()
		}
	}
	for _, p := range pair {
		if p.dev == nil {
			continue
		}
		for {
			select {
			case <-p.dev.PeerEvents():
				continue
			default:
				goto drained
			}
		}
	drained:
	}
}
