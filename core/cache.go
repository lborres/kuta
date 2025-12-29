package core

import (
	"sync"
	"sync/atomic"
	"time"
)

// TODO: Make this agnostic to whatever needs caching
type Cache interface {
	Get(tokenHash string) (*Session, error)
	Set(tokenHash string, session *Session) error
	Delete(tokenHash string) error
	Clear() error
}

type CacheWithStats interface {
	Cache
	Stats() CacheStats
}

type CacheConfig struct {
	TTL     time.Duration
	MaxSize int
}

// CacheStats are simple counters for cache behavior.
// These are intended for diagnostics and monitoring.
type CacheStats struct {
	Hits      int64         `json:"hits"`
	Misses    int64         `json:"misses"`
	Sets      int64         `json:"sets"`
	Deletes   int64         `json:"deletes"`
	Evictions int64         `json:"evictions"`
	Size      int           `json:"size"`
	TTL       time.Duration `json:"ttl"`
}

type InMemoryCache struct {
	cache   map[string]*cachedRecord // key: token hash
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
	session  *Session
	cachedAt time.Time
}

func NewInMemoryCache(c CacheConfig) *InMemoryCache {
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

func (c *InMemoryCache) Get(tokenHash string) (*Session, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	record, exists := c.cache[tokenHash]
	if !exists {
		atomic.AddInt64(&c.misses, 1)
		return nil, ErrCacheNotFound
	}

	if time.Since(record.cachedAt) > c.ttl {
		// expired
		atomic.AddInt64(&c.misses, 1)
		c.mu.RUnlock()

		if err := c.Delete(tokenHash); err != nil {
			return nil, err
		}

		c.mu.RLock()
		return nil, ErrCacheNotFound
	}

	atomic.AddInt64(&c.hits, 1)
	return record.session, nil
}

func (c *InMemoryCache) Set(tokenHash string, session *Session) error {
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

func (c *InMemoryCache) Delete(tokenHash string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, existed := c.cache[tokenHash]; existed {
		delete(c.cache, tokenHash)
		atomic.AddInt64(&c.deletes, 1)
	}
	return nil
}

func (c *InMemoryCache) Clear() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache = make(map[string]*cachedRecord)
	return nil
}

func (c *InMemoryCache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.cache)
}

func (c *InMemoryCache) Stats() CacheStats {
	return CacheStats{
		Hits:      atomic.LoadInt64(&c.hits),
		Misses:    atomic.LoadInt64(&c.misses),
		Sets:      atomic.LoadInt64(&c.sets),
		Deletes:   atomic.LoadInt64(&c.deletes),
		Evictions: atomic.LoadInt64(&c.evictions),
		Size:      c.Len(),
		TTL:       c.ttl,
	}
}
