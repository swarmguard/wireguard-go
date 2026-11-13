// SPDX-License-Identifier: MIT

package packetbudget

import (
	"fmt"
	"testing"
)

// BenchmarkBudgetPopulatedCache measures packet reuse while other packet
// sizes remain cached, as happens when small datagrams and TUN buffers share
// one runtime budget.
func BenchmarkBudgetPopulatedCache(b *testing.B) {
	for _, count := range []int{16, 128, 1024} {
		b.Run(fmt.Sprint(count), func(b *testing.B) {
			budget, err := New(Config{MaxBytes: 16 << 20, ControlReserveBytes: 256 << 10, MaxCachedBytes: 8 << 20, QueueEntries: 64})
			if err != nil {
				b.Fatal(err)
			}
			buffers := make([][]byte, count+16)
			for i := range buffers {
				size := 2048
				if i >= count {
					size = 65535
				}
				buffers[i] = budget.Get(size, false)
				if buffers[i] == nil {
					b.Fatal("cannot populate cache")
				}
			}
			for _, buffer := range buffers {
				budget.Put(buffer)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				for _, size := range []int{2048, 65535} {
					buffer := budget.Get(size, false)
					if buffer == nil || !budget.Put(buffer) {
						b.Fatal("cannot reuse buffer")
					}
				}
			}
		})
	}
}
