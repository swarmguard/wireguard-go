// SPDX-License-Identifier: MIT

// Package packetbudget accounts for backing storage shared by packet owners.
// It does not account for metadata, kernel buffers, or native TUN storage.
package packetbudget

import (
	"errors"
	"fmt"
	"sync"
)

// ErrExhausted identifies workspace reservations that cannot fit.
var ErrExhausted = errors.New("packet buffer budget exhausted or closed")

// Config contains immutable limits for one runtime. All byte counts include
// cached buffers. Data allocations cannot use ControlReserveBytes.
type Config struct {
	MaxBytes            int
	ControlReserveBytes int
	MaxCachedBytes      int
	QueueEntries        int
}

// Validate rejects invalid bounded configurations. A zero maximum selects the
// caller's legacy allocation path; New returns nil for that configuration.
func (c Config) Validate() error {
	if c.MaxBytes < 0 || c.ControlReserveBytes < 0 || c.MaxCachedBytes < 0 || c.QueueEntries < 0 {
		return fmt.Errorf("packet buffer limits must not be negative")
	}
	if c.MaxBytes == 0 {
		return nil
	}
	if c.ControlReserveBytes <= 0 || c.ControlReserveBytes >= c.MaxBytes {
		return fmt.Errorf("control reserve must be positive and smaller than max bytes")
	}
	if c.MaxCachedBytes <= 0 || c.MaxCachedBytes > c.MaxBytes {
		return fmt.Errorf("cached bytes must be positive and no larger than max bytes")
	}
	if c.QueueEntries < 16 {
		return fmt.Errorf("packet queues require at least 16 entries")
	}
	return nil
}

// Stats is a detached accounting snapshot. Outstanding counts checked-out
// buffers, not references or slices of those buffers.
type Stats struct {
	ManagedBytes, CachedBytes, DataBytes, PeakBytes, Outstanding int
	AllocationRejections, QueueRejections                        uint64
	Closed                                                       bool
}

type allocation struct {
	bytes   []byte
	control bool
	cached  bool
}

// Budget owns backing allocations for exactly one runtime. Get never waits
// for capacity. Put must receive the original slice starting at its base;
// slicing or transferring ownership does not transfer the accounting owner.
type Budget struct {
	mu          sync.Mutex
	config      Config
	stats       Stats
	allocations map[*byte]*allocation
	free        []*allocation
}

// New creates a budget, or nil for the legacy path.
func New(c Config) (*Budget, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	if c.MaxBytes == 0 {
		return nil, nil
	}
	return &Budget{config: c, allocations: make(map[*byte]*allocation)}, nil
}

// Config returns a detached copy of the immutable limits.
func (b *Budget) Config() Config { return b.config }

// Get acquires exactly size bytes of backing capacity. Control means a
// structurally valid control packet. Reader workspace uses data capacity;
// callers must still authenticate and rate-limit received control packets.
func (b *Budget) Get(size int, control bool) []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.stats.Closed || size <= 0 || size > b.config.MaxBytes || (!control && size > b.config.MaxBytes-b.config.ControlReserveBytes) {
		b.stats.AllocationRejections++
		return nil
	}
	for i, a := range b.free {
		if cap(a.bytes) == size && a.control == control {
			copy(b.free[i:], b.free[i+1:])
			b.free[len(b.free)-1] = nil
			b.free = b.free[:len(b.free)-1]
			a.cached = false
			b.stats.CachedBytes -= size
			b.stats.Outstanding++
			return a.bytes
		}
	}
	for b.stats.ManagedBytes > b.config.MaxBytes-size || (!control && b.stats.DataBytes > b.config.MaxBytes-b.config.ControlReserveBytes-size) {
		if len(b.free) == 0 {
			b.stats.AllocationRejections++
			return nil
		}
		i := len(b.free) - 1
		a := b.free[i]
		b.free[i] = nil
		b.free = b.free[:i]
		b.discard(a)
	}
	// Reserve under the same lock before allocating. make([]byte, size) has
	// exactly the charged capacity; allocator size-class overhead is excluded.
	b.stats.ManagedBytes += size
	if !control {
		b.stats.DataBytes += size
	}
	b.stats.Outstanding++
	if b.stats.ManagedBytes > b.stats.PeakBytes {
		b.stats.PeakBytes = b.stats.ManagedBytes
	}
	a := &allocation{bytes: make([]byte, size), control: control}
	b.allocations[&a.bytes[0]] = a
	return a.bytes
}

// Put returns exclusively owned storage. It reports false for unknown or
// already returned storage, preventing double accounting. The caller must not
// retain or reuse any reference after Put, including after cache reuse.
func (b *Budget) Put(buf []byte) bool {
	if len(buf) == 0 {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	a := b.allocations[&buf[0]]
	if a == nil || a.cached {
		return false
	}
	b.stats.Outstanding--
	// Cap cached allocation metadata to one 128-packet transport batch per
	// queue entry, in addition to the byte limit. Divide to avoid overflow.
	if b.stats.Closed || len(b.free)/128 >= b.config.QueueEntries || cap(a.bytes) > b.config.MaxCachedBytes-b.stats.CachedBytes {
		b.discard(a)
	} else {
		a.cached = true
		b.stats.CachedBytes += cap(a.bytes)
		b.free = append(b.free, a)
	}
	return true
}

func (b *Budget) discard(a *allocation) {
	size := cap(a.bytes)
	delete(b.allocations, &a.bytes[0])
	b.stats.ManagedBytes -= size
	if !a.control {
		b.stats.DataBytes -= size
	}
	if a.cached {
		b.stats.CachedBytes -= size
	}
	a.bytes = nil
	if b.stats.Closed && b.stats.Outstanding == 0 {
		b.allocations = nil
	}
}

// RejectQueue records admission failure without logging per packet.
func (b *Budget) RejectQueue() {
	b.mu.Lock()
	b.stats.QueueRejections++
	b.mu.Unlock()
}

// Snapshot returns current accounting without exposing mutable ownership.
func (b *Budget) Snapshot() Stats {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.stats
}

// Close rejects new allocations and discards idle buffers. Outstanding owners
// remain charged until they return storage; late returns cannot recache it.
func (b *Budget) Close() {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.stats.Closed = true
	for _, a := range b.free {
		b.discard(a)
	}
	b.free = nil
}

// Admit serializes a nonblocking queue publication with runtime closure.
// publish must not wait, allocate packet storage, or call back into Budget.
// False records a queue rejection, including attempts after closure.
func (b *Budget) Admit(publish func() bool) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.stats.Closed && publish() {
		return true
	}
	b.stats.QueueRejections++
	return false
}
