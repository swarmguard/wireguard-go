/* SPDX-License-Identifier: MIT */

package tun

import (
	"golang.org/x/sys/unix"
	"os"
	"runtime"
	"testing"
)

func benchmarkBatchCapacity(b *testing.B) int {
	b.Helper()
	switch os.Getenv("SG_BENCH_BATCH") {
	case "", "128":
		return 128
	case "8":
		return 8
	default:
		b.Fatal("invalid SG_BENCH_BATCH")
		return 0
	}
}

// BenchmarkNativeOffloadSetup measures native offload allocations without ioctl.
func BenchmarkNativeOffloadSetup(b *testing.B) {
	disabled := benchmarkBatchCapacity(b) == 8
	var dev NativeTun
	setup := func() {
		dev = NativeTun{}
		if err := dev.configureOffloads(unix.IFF_VNET_HDR, Options{DisableOffloads: disabled}, func(int) error { return nil }); err != nil {
			b.Fatal(err)
		}
	}
	setup()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		setup()
	}
	b.StopTimer()
	if dev.BatchSize() == 0 {
		b.Fatal("not configured")
	}
}

// BenchmarkNativePacketRead measures user-space handling of 128 packets.
// Compact inputs are already segmented, so kernel segmentation cost is excluded.
func BenchmarkNativePacketRead(b *testing.B) {
	disabled := benchmarkBatchCapacity(b) == 8
	aggregate := batchAggregate("tcp4", 128)
	packets, sizes := batchBuffers(128)
	if _, err := handleVirtioRead(aggregate, packets, sizes, 16); err != nil {
		b.Fatal(err)
	}
	for i := range packets {
		packets[i] = append(make([]byte, virtioNetHdrLen), packets[i][16:16+sizes[i]]...)
	}
	bufs, outSizes := batchBuffers(128)
	read := func() {
		if disabled {
			for _, packet := range packets {
				if _, err := readPlain(packet, true, bufs[0], outSizes, 16); err != nil {
					b.Fatal(err)
				}
			}
		} else {
			if _, err := handleVirtioRead(aggregate, bufs, outSizes, 16); err != nil {
				b.Fatal(err)
			}
		}
	}
	read()
	b.ReportAllocs()
	b.SetBytes(127*100 + 37)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		read()
	}
}

// nativeHeapFixture keeps the measured object on the heap and live across GC.
var nativeHeapFixture *NativeTun

// TestNativeRetainedHeap measures offload state separately from WireGuard devices.
func TestNativeRetainedHeap(t *testing.T) {
	if os.Getenv("SG_BATCH_MEASURE") != "1" {
		t.Skip("opt-in heap measurement")
	}
	disabled := os.Getenv("SG_BENCH_BATCH") == "8"
	runtime.GC()
	runtime.GC()
	var before, live, closed runtime.MemStats
	runtime.ReadMemStats(&before)
	for cycle := 0; cycle < 10; cycle++ {
		nativeHeapFixture = &NativeTun{}
		if err := nativeHeapFixture.configureOffloads(unix.IFF_VNET_HDR, Options{DisableOffloads: disabled}, func(int) error { return nil }); err != nil {
			t.Fatal(err)
		}
		runtime.GC()
		runtime.GC()
		runtime.ReadMemStats(&live)
		runtime.KeepAlive(nativeHeapFixture)
		nativeHeapFixture = nil
		runtime.GC()
		runtime.GC()
		runtime.ReadMemStats(&closed)
		t.Logf("disabled=%t cycle=%d before=%d live=%d closed=%d", disabled, cycle, before.HeapAlloc, live.HeapAlloc, closed.HeapAlloc)
	}
}
