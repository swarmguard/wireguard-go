// SPDX-License-Identifier: MIT
package packetbudget

import "sync"

// Cache is a bounded free list for packet metadata. Payload storage must be
// returned to Budget separately before caching a wrapper. Closing a cache
// discards idle objects and prevents late returns from retaining objects.
type Cache[T any] struct {
	mu     sync.Mutex
	limit  int
	free   []T
	closed bool
}

// NewCache creates an empty metadata cache with a fixed object limit.
func NewCache[T any](limit int) *Cache[T] { return &Cache[T]{limit: limit} }

// Take removes a cached object, or returns the zero value when empty.
func (c *Cache[T]) Take() T {
	c.mu.Lock()
	defer c.mu.Unlock()
	var zero T
	if len(c.free) == 0 {
		return zero
	}
	i := len(c.free) - 1
	object := c.free[i]
	c.free[i] = zero
	c.free = c.free[:i]
	return object
}

// Put caches an object only while open and below its object limit.
func (c *Cache[T]) Put(object T) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed && len(c.free) < c.limit {
		c.free = append(c.free, object)
	}
}

// Close discards idle objects and prevents further caching.
func (c *Cache[T]) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	c.free = nil
}

// Reopen allows the same owner to reuse an empty cache after its readers have
// stopped. It does not reopen or replace the payload budget.
func (c *Cache[T]) Reopen() { c.mu.Lock(); c.closed = false; c.mu.Unlock() }
