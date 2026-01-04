package cache

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/lborres/kuta/core"
)

// InMemoryCache implements an in-memory session cache
type InMemoryCache struct {
	cache   map[string]*cachedRecord
	mu      sync.RWMutex
	ttl     time.Duration
	maxSize int

	// counters
	hits      int64
	misses    int64
	sets      int64
	deletes   int64
	evictions int64
}

type cachedRecord struct {
	session  *core.Session
	cachedAt time.Time
}

// NewInMemoryCache creates a new in-memory cache
func NewInMemoryCache(c core.CacheConfig) *InMemoryCache {
	if c.TTL == 0 {
		c.TTL = 5 * time.Minute
	}
	if c.MaxSize == 0 {
		c.MaxSize = 500
	}

	return &InMemoryCache{
		cache:   make(map[string]*cachedRecord),
		ttl:     c.TTL,
		maxSize: c.MaxSize,
	}
}

// Get retrieves a session from cache
func (c *InMemoryCache) Get(tokenHash string) (*core.Session, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	record, exists := c.cache[tokenHash]
	if !exists {
		atomic.AddInt64(&c.misses, 1)
		return nil, core.ErrCacheNotFound
	}

	if time.Since(record.cachedAt) > c.ttl {
		// expired
		atomic.AddInt64(&c.misses, 1)
		c.mu.RUnlock()

		if err := c.Delete(tokenHash); err != nil {
			return nil, err
		}

		c.mu.RLock()
		return nil, core.ErrCacheNotFound
	}

	atomic.AddInt64(&c.hits, 1)
	return record.session, nil
}

// Set stores a session in cache
func (c *InMemoryCache) Set(tokenHash string, session *core.Session) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Simple eviction if full
	if len(c.cache) >= c.maxSize {
		for k := range c.cache {
			delete(c.cache, k)
			atomic.AddInt64(&c.evictions, 1)
			break
		}
	}

	c.cache[tokenHash] = &cachedRecord{
		session:  session,
		cachedAt: time.Now(),
	}

	atomic.AddInt64(&c.sets, 1)
	return nil
}

// Delete removes a session from cache
func (c *InMemoryCache) Delete(tokenHash string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, existed := c.cache[tokenHash]; existed {
		delete(c.cache, tokenHash)
		atomic.AddInt64(&c.deletes, 1)
	}
	return nil
}

// Clear removes all sessions from cache
func (c *InMemoryCache) Clear() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache = make(map[string]*cachedRecord)
	return nil
}

// Len returns the number of cached sessions
func (c *InMemoryCache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.cache)
}

// Stats returns cache statistics
func (c *InMemoryCache) Stats() core.CacheStats {
	return core.CacheStats{
		Hits:      atomic.LoadInt64(&c.hits),
		Misses:    atomic.LoadInt64(&c.misses),
		Sets:      atomic.LoadInt64(&c.sets),
		Deletes:   atomic.LoadInt64(&c.deletes),
		Evictions: atomic.LoadInt64(&c.evictions),
		Size:      c.Len(),
		TTL:       c.ttl,
	}
}
