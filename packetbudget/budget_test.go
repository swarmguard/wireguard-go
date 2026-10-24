// SPDX-License-Identifier: MIT
package packetbudget

import (
	"encoding/binary"
	"sync"
	"testing"
)

func testBudget(t testing.TB) *Budget {
	t.Helper()
	b, err := New(Config{MaxBytes: 1024, ControlReserveBytes: 256, MaxCachedBytes: 512, QueueEntries: 16})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestAccounting exercises cache eviction, transfer, copies, reserve and close.
func TestAccounting(t *testing.T) {
	b := testBudget(t)
	a := b.Get(512, false)
	if a == nil || cap(a) != 512 {
		t.Fatal("backing capacity")
	}
	if b.Get(257, false) != nil {
		t.Fatal("data entered reserve")
	}
	copyBuffer := b.Get(256, false)
	copy(copyBuffer, a[:256])
	control := b.Get(256, true)
	if control == nil || b.Get(1, true) != nil {
		t.Fatal("total bound")
	}
	if !b.Put(a) || b.Put(a) {
		t.Fatal("double return")
	}
	if b.Snapshot().CachedBytes != 512 {
		t.Fatal(b.Snapshot())
	}
	// A larger control allocation evicts idle data, without changing active data.
	b.Put(control)
	large := b.Get(600, true)
	if large == nil {
		t.Fatal("cache not evicted")
	}
	s := b.Snapshot()
	if s.ManagedBytes != 856 || s.DataBytes != 256 || s.Outstanding != 2 {
		t.Fatal(s)
	}
	b.Close()
	if b.Get(1, true) != nil {
		t.Fatal("allocation after close")
	}
	b.Put(copyBuffer)
	b.Put(large)
	s = b.Snapshot()
	if s.ManagedBytes != 0 || s.CachedBytes != 0 || s.Outstanding != 0 {
		t.Fatal(s)
	}
}

// TestConcurrentClose proves late returns stay with the old budget.
func TestConcurrentClose(t *testing.T) {
	for range 20 {
		b := testBudget(t)
		replacement := testBudget(t)
		var wg sync.WaitGroup
		for range 16 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for range 100 {
					if buf := b.Get(64, false); buf != nil {
						b.Put(buf)
					}
				}
			}()
		}
		b.Close()
		wg.Wait()
		if s := b.Snapshot(); s.ManagedBytes != 0 || s.Outstanding != 0 || s.PeakBytes > 1024 {
			t.Fatal(s)
		}
		if s := replacement.Snapshot(); s.ManagedBytes != 0 || s.Closed {
			t.Fatal(s)
		}
	}
}

// TestControlFormat rejects data disguised by a control prefix or length.
func TestControlFormat(t *testing.T) {
	for typ, size := range map[uint32]int{1: 148, 2: 92, 3: 64, 4: 32, 5: 32, 6: 40, 7: 40} {
		for _, n := range []int{size - 1, size, size + 1} {
			buf := make([]byte, n)
			binary.LittleEndian.PutUint32(buf, typ)
			if IsControl(buf) != (n == size) {
				t.Fatalf("type=%d size=%d", typ, n)
			}
		}
	}
	if IsControl(nil) || IsControl([]byte{1, 0, 0}) {
		t.Fatal("short control")
	}
}

// BenchmarkBudget measures a warmed single-owner allocation/return cycle.
func BenchmarkBudget(b *testing.B) {
	budget, _ := New(Config{MaxBytes: 8 << 20, ControlReserveBytes: 256 << 10, MaxCachedBytes: 1 << 20, QueueEntries: 64})
	budget.Put(budget.Get(2048, false))
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		buf := budget.Get(2048, false)
		budget.Put(buf)
	}
}

// TestMetadataCacheClose bounds idle wrappers and discards late returns.
func TestMetadataCacheClose(t *testing.T) {
	c := NewCache[*int](2)
	a, b, d := 1, 2, 3
	c.Put(&a)
	c.Put(&b)
	c.Put(&d)
	if len(c.free) != 2 {
		t.Fatal("unbounded metadata cache")
	}
	c.Close()
	c.Put(&d)
	if c.Take() != nil || len(c.free) != 0 {
		t.Fatal("retained after close")
	}
	c.Reopen()
	c.Put(&d)
	if c.Take() != &d {
		t.Fatal("reopen")
	}
}

// TestAdmissionClosure prevents publication after the budget closes.
func TestAdmissionClosure(t *testing.T) {
	b := testBudget(t)
	entered, finish := make(chan struct{}), make(chan struct{})
	completed := make(chan struct{})
	go func() { b.Admit(func() bool { close(entered); <-finish; return true }); close(completed) }()
	<-entered
	closed := make(chan struct{})
	go func() { b.Close(); close(closed) }()
	close(finish)
	<-completed
	<-closed
	called := false
	if b.Admit(func() bool { called = true; return true }) || called {
		t.Fatal("admitted after closure")
	}
}
