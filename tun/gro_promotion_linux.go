//go:build linux

/* SPDX-License-Identifier: MIT */

package tun

// GRO promotion supports the native maximum batch, with at most eight MiB
// of cached payload storage per TUN.
const (
	groPromotionMaxHeads   = 128
	groPromotionBufferSize = 1 << 16
)

// groPromotion owns bounded workspace for synchronous GRO head growth.
// The enclosing NativeTun write mutex protects its entire lifetime.
type groPromotion struct {
	buffers   [groPromotionMaxHeads][]byte
	originals [groPromotionMaxHeads][]byte
	used      int
	active    bool
	closed    bool
}

// begin retains caller slice headers so temporary heads never escape Write.
func (p *groPromotion) begin(bufs [][]byte) {
	p.used = 0
	p.active = !p.closed && len(bufs) <= len(p.originals)
	if p.active {
		copy(p.originals[:], bufs)
	}
}

// ensure grows only a head that has a coalescing candidate. Exhaustion leaves
// the packet unmerged rather than growing the cache or retaining packet owners.
func (p *groPromotion) ensure(bufs [][]byte, index, needed int) bool {
	if p == nil || !p.active || needed > groPromotionBufferSize || p.used == len(p.buffers) {
		return false
	}
	if cap(bufs[index]) >= needed {
		return true
	}
	// Full message buffers keep the original bounded aggregation behavior.
	if cap(bufs[index]) >= groPromotionBufferSize-1 {
		return false
	}
	slot := p.used
	p.used++
	if p.buffers[slot] == nil {
		p.buffers[slot] = make([]byte, groPromotionBufferSize)
	}
	head := p.buffers[slot][:len(bufs[index])]
	copy(head, bufs[index])
	bufs[index] = head
	return true
}

// finish restores caller headers after synchronous writes and clears borrowed
// references while retaining at most eight MiB of owned workspace.
func (p *groPromotion) finish(bufs [][]byte) {
	if p.active {
		copy(bufs, p.originals[:len(bufs)])
		clear(p.originals[:len(bufs)])
	}
	p.used = 0
	p.active = false
}
