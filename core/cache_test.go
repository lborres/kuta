package core

import (
	"testing"
	"time"
)

func TestInMemoryCacheGetSetShouldStoreAndRetrieve(t *testing.T) {
	cache := NewInMemoryCache(CacheConfig{
		TTL:     5 * time.Minute,
		MaxSize: 500,
	})

	session := &Session{
		ID:        "session123",
		UserID:    "user456",
		TokenHash: "hash789",
		ExpiresAt: time.Now().Add(24 * time.Hour),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Test Set
	err := cache.Set("hash789", session)
	if err != nil {
		t.Fatalf("Set failed: %v", err)
	}

	// Test Get
	retrieved, err := cache.Get("hash789")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	if retrieved.ID != session.ID {
		t.Errorf("Expected ID %s, got %s", session.ID, retrieved.ID)
	}

	if retrieved.UserID != session.UserID {
		t.Errorf("Expected UserID %s, got %s", session.UserID, retrieved.UserID)
	}
}

func TestInMemoryCacheGetNonExistentShouldReturnErrCacheNotFound(t *testing.T) {
	cache := NewInMemoryCache(CacheConfig{
		TTL:     5 * time.Minute,
		MaxSize: 500,
	})

	_, err := cache.Get("nonexistent")
	if err != ErrCacheNotFound {
		t.Errorf("Expected ErrCacheNotFound, got %v", err)
	}
}

func TestInMemoryCacheExpiryShouldExpireEntriesAfterTTL(t *testing.T) {
	cache := NewInMemoryCache(CacheConfig{
		TTL:     100 * time.Millisecond,
		MaxSize: 500,
	})

	session := &Session{
		ID:        "session123",
		TokenHash: "hash789",
		ExpiresAt: time.Now().Add(24 * time.Hour),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	cache.Set("hash789", session)

	// Should exist immediately
	_, err := cache.Get("hash789")
	if err != nil {
		t.Error("Session should exist immediately after Set")
	}

	// Wait for TTL to expire
	time.Sleep(150 * time.Millisecond)

	// Should be expired and removed from cache
	_, err = cache.Get("hash789")
	if err != ErrCacheNotFound {
		t.Error("Session should be expired and removed from cache")
	}

	if cache.Len() != 0 {
		t.Errorf("Cache should be empty after expired entry removed, got size %d", cache.Len())
	}
}

func TestInMemoryCacheDeleteShouldRemoveEntry(t *testing.T) {
	cache := NewInMemoryCache(CacheConfig{
		TTL:     5 * time.Minute,
		MaxSize: 500,
	})

	session := &Session{
		ID:        "session123",
		TokenHash: "hash789",
		ExpiresAt: time.Now().Add(24 * time.Hour),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	cache.Set("hash789", session)

	// Verify it exists
	_, err := cache.Get("hash789")
	if err != nil {
		t.Error("Session should exist before Delete")
	}

	// Delete
	err = cache.Delete("hash789")
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	// Should not exist anymore
	_, err = cache.Get("hash789")
	if err != ErrCacheNotFound {
		t.Error("Session should be deleted")
	}
}

func TestInMemoryCacheDeleteNonExistentShouldNotError(t *testing.T) {
	cache := NewInMemoryCache(CacheConfig{
		TTL:     5 * time.Minute,
		MaxSize: 500,
	})

	// Deleting non-existent key should not error
	err := cache.Delete("nonexistent")
	if err != nil {
		t.Errorf("Delete of non-existent key should not error, got %v", err)
	}
}

func TestInMemoryCacheClearShouldRemoveAllEntries(t *testing.T) {
	cache := NewInMemoryCache(CacheConfig{
		TTL:     5 * time.Minute,
		MaxSize: 500,
	})

	session1 := &Session{ID: "session1", TokenHash: "hash1", CreatedAt: time.Now(), UpdatedAt: time.Now()}
	session2 := &Session{ID: "session2", TokenHash: "hash2", CreatedAt: time.Now(), UpdatedAt: time.Now()}
	session3 := &Session{ID: "session3", TokenHash: "hash3", CreatedAt: time.Now(), UpdatedAt: time.Now()}

	cache.Set("hash1", session1)
	cache.Set("hash2", session2)
	cache.Set("hash3", session3)

	// Verify all exist
	if cache.Len() != 3 {
		t.Errorf("Expected 3 sessions in cache, got %d", cache.Len())
	}

	// Clear all
	err := cache.Clear()
	if err != nil {
		t.Fatalf("Clear failed: %v", err)
	}

	// All should be gone
	if cache.Len() != 0 {
		t.Errorf("Cache should be empty after Clear, got size %d", cache.Len())
	}

	_, err = cache.Get("hash1")
	if err != ErrCacheNotFound {
		t.Error("hash1 should be cleared")
	}

	_, err = cache.Get("hash2")
	if err != ErrCacheNotFound {
		t.Error("hash2 should be cleared")
	}

	_, err = cache.Get("hash3")
	if err != ErrCacheNotFound {
		t.Error("hash3 should be cleared")
	}
}

func TestInMemoryCacheMaxLenShouldEvictWhenOverCapacity(t *testing.T) {
	cache := NewInMemoryCache(CacheConfig{
		TTL:     5 * time.Minute,
		MaxSize: 2,
	}) // Max 2 entries

	session1 := &Session{ID: "session1", TokenHash: "hash1", CreatedAt: time.Now(), UpdatedAt: time.Now()}
	session2 := &Session{ID: "session2", TokenHash: "hash2", CreatedAt: time.Now(), UpdatedAt: time.Now()}
	session3 := &Session{ID: "session3", TokenHash: "hash3", CreatedAt: time.Now(), UpdatedAt: time.Now()}

	cache.Set("hash1", session1)
	cache.Set("hash2", session2)

	if cache.Len() != 2 {
		t.Errorf("Expected 2 sessions, got %d", cache.Len())
	}

	// Adding 3rd should evict one
	cache.Set("hash3", session3)

	// Should only have 2 entries
	if cache.Len() != 2 {
		t.Errorf("Expected size 2 after eviction, got %d", cache.Len())
	}

	// At least one of the first two should be evicted
	count := 0
	if _, err := cache.Get("hash1"); err == nil {
		count++
	}
	if _, err := cache.Get("hash2"); err == nil {
		count++
	}
	if _, err := cache.Get("hash3"); err == nil {
		count++
	}

	if count != 2 {
		t.Errorf("Expected exactly 2 sessions in cache, found %d", count)
	}
}

func TestInMemoryCacheLenShouldReflectOperations(t *testing.T) {
	cache := NewInMemoryCache(CacheConfig{
		TTL:     5 * time.Minute,
		MaxSize: 500,
	})

	if cache.Len() != 0 {
		t.Error("New cache should be empty")
	}

	cache.Set("hash1", &Session{ID: "1", CreatedAt: time.Now(), UpdatedAt: time.Now()})
	if cache.Len() != 1 {
		t.Errorf("Expected size 1, got %d", cache.Len())
	}

	cache.Set("hash2", &Session{ID: "2", CreatedAt: time.Now(), UpdatedAt: time.Now()})
	if cache.Len() != 2 {
		t.Errorf("Expected size 2, got %d", cache.Len())
	}

	cache.Delete("hash1")
	if cache.Len() != 1 {
		t.Errorf("Expected size 1 after delete, got %d", cache.Len())
	}

	cache.Clear()
	if cache.Len() != 0 {
		t.Errorf("Expected size 0 after clear, got %d", cache.Len())
	}
}

func TestInMemoryCacheConcurrentReadWriteShouldNotRaceOrPanic(t *testing.T) {
	cache := NewInMemoryCache(CacheConfig{
		TTL:     5 * time.Minute,
		MaxSize: 500,
	})
	done := make(chan bool, 200)

	session := &Session{
		ID:        "session123",
		TokenHash: "hash789",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// 100 writers
	for i := 0; i < 100; i++ {
		go func(id int) {
			cache.Set("hash"+string(rune(id)), session)
			done <- true
		}(i)
	}

	// 100 readers
	for i := 0; i < 100; i++ {
		go func() {
			cache.Get("hash789")
			done <- true
		}()
	}

	// Wait for all
	for i := 0; i < 200; i++ {
		<-done
	}

	// Should not panic or have race conditions
}

func TestInMemoryCacheConcurrentDeleteShouldResultInEmptyCache(t *testing.T) {
	cache := NewInMemoryCache(CacheConfig{
		TTL:     5 * time.Minute,
		MaxSize: 500,
	})

	// Pre-populate
	for i := 0; i < 100; i++ {
		session := &Session{ID: string(rune(i)), CreatedAt: time.Now(), UpdatedAt: time.Now()}
		cache.Set("hash"+string(rune(i)), session)
	}

	done := make(chan bool, 100)

	// Delete concurrently
	for i := 0; i < 100; i++ {
		go func(id int) {
			cache.Delete("hash" + string(rune(id)))
			done <- true
		}(i)
	}

	// Wait for all
	for i := 0; i < 100; i++ {
		<-done
	}

	// Cache should be empty
	if cache.Len() != 0 {
		t.Errorf("Expected empty cache, got size %d", cache.Len())
	}
}
