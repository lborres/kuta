package core

import (
	"sync"
	"time"
)

// TODO: Make this agnostic to whatever needs caching
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
	cache   map[string]*cachedRecord // key: token hash
	mu      sync.RWMutex
	ttl     time.Duration
	maxSize int
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
		return nil, ErrCacheNotFound
	}

	if time.Since(record.cachedAt) > c.ttl {
		c.mu.RUnlock()

		if err := c.Delete(tokenHash); err != nil {
			return nil, err
		}

		c.mu.RLock()
		return nil, ErrCacheNotFound
	}

	return record.session, nil
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

	c.cache[tokenHash] = &cachedRecord{
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
	c.cache = make(map[string]*cachedRecord)
	return nil
}

func (c *InMemoryCache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.cache)
}
