// SPDX-License-Identifier: MIT
//go:build !race

package tun

// Allocation counts are measured without race instrumentation, which changes
// allocation behavior. Functional and lifetime checks run with -race as well.
import (
	"runtime"
	"testing"
	"unsafe"

	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// TestReceiveGroupingBoundedMetadata verifies storage and warmed write allocations.
func TestReceiveGroupingBoundedMetadata(t *testing.T) {
	d, _ := groupTestTun(t)
	g := d.receiveGrouping
	metadata := int(unsafe.Sizeof(*g)) + cap(g.indexes)*int(unsafe.Sizeof(int(0)))
	for _, v := range g.tcp.itemsPool {
		metadata += cap(v) * int(unsafe.Sizeof(tcpGROItem{}))
	}
	for _, v := range g.udp.itemsPool {
		metadata += cap(v) * int(unsafe.Sizeof(udpGROItem{}))
	}
	if metadata > 48<<10 {
		t.Fatal(metadata)
	} // Remaining space covers the two bounded maps.
	p := tcp4Packet(ip4PortA, ip4PortB, header.TCPFlagAck, 1200, 1)
	q := tcp4Packet(ip4PortA, ip4PortB, header.TCPFlagAck, 1200, 1201)
	write := func(p []byte) (int, error) { return len(p), nil }
	if a := testing.AllocsPerRun(100, func() {
		if _, err := d.writeGroupedTo([][]byte{p, q}, offset, write); err != nil {
			panic(err)
		}
	}); a != 0 {
		t.Fatal(a)
	}
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for i := 0; i < 100; i++ {
		d.closeReceiveGrouping()
		if e := d.initReceiveGrouping(g.budget); e != nil {
			t.Fatal(e)
		}
	}
	runtime.ReadMemStats(&after)
	// Data buffers not retained by the 64 KiB cache are subtracted conservatively.
	per := int((after.TotalAlloc-before.TotalAlloc)/100) - 8*16384
	if per > 65536 {
		t.Fatalf("metadata allocation bound exceeded: %d", per)
	}
	t.Logf("metadata fixed backing estimate=%d; allocation upper estimate=%d", metadata, per)
}
