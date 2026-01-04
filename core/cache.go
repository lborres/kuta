package core

import (
	"time"
)

// Cache defines session caching operations
type Cache interface {
	Get(tokenHash string) (*Session, error)
	Set(tokenHash string, session *Session) error
	Delete(tokenHash string) error
	Clear() error
}

// CacheWithStats extends Cache with statistics tracking
type CacheWithStats interface {
	Cache
	Stats() CacheStats
}

// CacheConfig configures cache behavior
type CacheConfig struct {
	TTL     time.Duration
	MaxSize int
}

// CacheStats tracks cache performance metrics
type CacheStats struct {
	Hits      int64         `json:"hits"`
	Misses    int64         `json:"misses"`
	Sets      int64         `json:"sets"`
	Deletes   int64         `json:"deletes"`
	Evictions int64         `json:"evictions"`
	Size      int           `json:"size"`
	TTL       time.Duration `json:"ttl"`
}
