package nfs

// Handle-keyed write fd cache (agent-data-workspace issue #235, inode
// identity layer SPEC #234 / ADR-0022 Q5): WRITE RPCs resolve the file
// ONCE per handle and keep the fd — subsequent writes on the same
// handle go through the cached billy.File instead of re-opening by
// path. Identity follows the handle, not the name: rename and unlink
// NEVER invalidate the cache (that decoupling is the entire point —
// the overlay layer's trackedFile machinery owns the write-session
// semantics that depend on it).
//
// Disabled by default: a nil cache on the Server keeps the exact
// legacy open-seek-write-close behavior per WRITE RPC.

import (
	"container/list"
	"sync"
	"time"

	billy "github.com/go-git/go-billy/v5"
)

// writeHandleEntry is one cached open file. The per-entry mutex
// serializes concurrent WRITE RPCs racing on the same handle; the LRU
// element is the cache's own bookkeeping.
type writeHandleEntry struct {
	mu      sync.Mutex
	file    billy.File
	lastUse time.Time
	element *list.Element
}

// writeHandleCache is the handle-keyed fd table. All methods are safe
// for concurrent use.
type writeHandleCache struct {
	mu      sync.Mutex
	cap     int
	idleTTL time.Duration
	entries map[string]*writeHandleEntry
	lru     *list.List // front = most recently used
	now     func() time.Time
	// resolve serializes the miss→open→put window per handle: two
	// WRITE RPCs racing on a cold handle must not both open by path.
	// Mutexes live for the cache's lifetime — bounded by the handle
	// space, the same order as the transport's own handle cache.
	resolve map[string]*sync.Mutex
}

// WithWriteHandleCache enables the write fd cache on the server.
// capacity <= 0 or idleTTL <= 0 keeps the cache disabled (nil) —
// capacity 0 = the mechanism is off (legacy semantics). The server is
// returned for fluent use before Serve.
func WithWriteHandleCache(s *Server, capacity int, idleTTL time.Duration) *Server {
	if capacity <= 0 || idleTTL <= 0 {
		return s
	}
	s.writeCache = &writeHandleCache{
		cap:     capacity,
		idleTTL: idleTTL,
		entries: make(map[string]*writeHandleEntry, capacity),
		lru:     list.New(),
		now:     time.Now,
		resolve: make(map[string]*sync.Mutex),
	}
	return s
}

// resolveMu returns the per-handle resolution lock, taking it. The
// caller releases it once the entry is resolved (hit, or miss+open+put)
// and the entry's own mutex covers the write span.
func (c *writeHandleCache) resolveMu(handle []byte) *sync.Mutex {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := string(handle)
	m, ok := c.resolve[key]
	if !ok {
		m = &sync.Mutex{}
		c.resolve[key] = m
	}
	m.Lock()
	return m
}

// get returns the cached entry for the handle — pre-locked for the
// caller's write span (release unlocks) — or nil on miss. Pre-locking
// inside the cache lock closes the race against LRU/idle eviction
// closing the fd between hit and write. A nil receiver is the disabled
// cache: every lookup misses.
func (c *writeHandleCache) get(handle []byte) *writeHandleEntry {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sweepLocked()
	e, ok := c.entries[string(handle)]
	if !ok {
		return nil
	}
	e.mu.Lock()
	e.lastUse = c.now()
	c.lru.MoveToFront(e.element)
	return e
}

// put registers a freshly opened file under the handle and returns the
// entry pre-locked for the caller's write span (release unlocks),
// evicting the least-recently-used entry (closing its fd) when over
// capacity. A nil receiver is the disabled cache: it returns nil and
// the caller keeps the legacy close-after-write behavior.
func (c *writeHandleCache) put(handle []byte, file billy.File) *writeHandleEntry {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sweepLocked()
	key := string(handle)
	if old, ok := c.entries[key]; ok {
		// Same handle re-registered after a get miss — the previous fd
		// must not leak (serialize on it before closing: a write may
		// still be in flight on it).
		old.mu.Lock()
		_ = old.file.Close()
		old.mu.Unlock()
		c.lru.Remove(old.element)
		delete(c.entries, key)
	}
	e := &writeHandleEntry{file: file, lastUse: c.now()}
	e.element = c.lru.PushFront(e)
	c.entries[key] = e
	for c.lru.Len() > c.cap {
		oldest := c.lru.Back()
		if oldest == nil {
			break
		}
		victim := oldest.Value.(*writeHandleEntry)
		victim.mu.Lock()
		_ = victim.file.Close()
		victim.mu.Unlock()
		c.lru.Remove(oldest)
		for k, v := range c.entries {
			if v == victim {
				delete(c.entries, k)
				break
			}
		}
	}
	e.mu.Lock()
	return e
}

// release unlocks the entry after a cached write span.
func (c *writeHandleCache) release(e *writeHandleEntry) {
	if c == nil || e == nil {
		return
	}
	e.mu.Unlock()
}

// sweepLocked closes and drops entries idle beyond the TTL. Caller
// holds c.mu; entry locks are taken around the close only.
func (c *writeHandleCache) sweepLocked() {
	if c.idleTTL <= 0 || len(c.entries) == 0 {
		return
	}
	now := c.now()
	for key, e := range c.entries {
		if now.Sub(e.lastUse) > c.idleTTL {
			e.mu.Lock()
			_ = e.file.Close()
			e.mu.Unlock()
			c.lru.Remove(e.element)
			delete(c.entries, key)
		}
	}
}

// len reports the live entry count (test surface).
func (c *writeHandleCache) len() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}
