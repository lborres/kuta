package core

import (
	"sync"
	"time"
)

type Cache interface {
	Get(tokenHash string) (*Session, error)
	Set(tokenHash string, session *Session) error
	Delete(tokenHash string) error
	Clear() error
}

type CacheConfig struct {
	TTL     time.Duration
	MaxSize int
}

type InMemoryCache struct {
	cache   map[string]*cachedEntry // key: token hash
	mu      sync.RWMutex
	ttl     time.Duration
	maxSize int
}

type cachedEntry struct {
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
		cache:   make(map[string]*cachedEntry),
		ttl:     c.TTL,
		maxSize: c.MaxSize,
	}
}

func (c *InMemoryCache) Get(tokenHash string) (*Session, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, exists := c.cache[tokenHash]
	if !exists {
		return nil, ErrCacheNotFound
	}

	if time.Since(entry.cachedAt) > c.ttl {
		c.mu.RUnlock()

		if err := c.Delete(tokenHash); err != nil {
			return nil, err
		}

		c.mu.RLock()
		return nil, ErrCacheNotFound
	}

	return entry.session, nil
}

func (c *InMemoryCache) Set(tokenHash string, session *Session) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Simple eviction if full
	if len(c.cache) >= c.maxSize {
		for k := range c.cache {
			delete(c.cache, k)
			break
		}
	}

	c.cache[tokenHash] = &cachedEntry{
		session:  session,
		cachedAt: time.Now(),
	}

	return nil
}

func (c *InMemoryCache) Delete(tokenHash string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.cache, tokenHash)
	return nil
}

func (c *InMemoryCache) Clear() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache = make(map[string]*cachedEntry)
	return nil
}

func (c *InMemoryCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.cache)
}
