package ratelimit

import (
	"sync"
	"time"
)

// Limiter implements a sliding window rate limiter using standard library only.
// It tracks requests per key (e.g., IP address, user ID) within a time window.
type Limiter struct {
	requests map[string][]time.Time
	mu       sync.RWMutex
	limit    int           // Maximum requests allowed
	window   time.Duration // Time window for the limit
	stopChan chan struct{}
}

// New creates a new rate limiter with the specified limit and time window.
// Example: New(10, time.Minute) allows 10 requests per minute per key.
func New(limit int, window time.Duration) *Limiter {
	l := &Limiter{
		requests: make(map[string][]time.Time),
		limit:    limit,
		window:   window,
		stopChan: make(chan struct{}),
	}

	// Start background cleanup to prevent memory leaks
	go l.cleanup()

	return l
}

// Allow checks if a request should be allowed for the given key.
// Returns true if the request is within limits, false if rate limited.
func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()

	// Get existing requests for this key
	times := l.requests[key]

	// Filter out requests outside the current window (sliding window)
	validTimes := make([]time.Time, 0, len(times))
	cutoff := now.Add(-l.window)
	for _, t := range times {
		if t.After(cutoff) {
			validTimes = append(validTimes, t)
		}
	}

	// Check if limit exceeded
	if len(validTimes) >= l.limit {
		return false
	}

	// Add current request
	validTimes = append(validTimes, now)
	l.requests[key] = validTimes

	return true
}

// Reset removes all tracked requests for a specific key.
// Useful for testing or manual intervention.
func (l *Limiter) Reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.requests, key)
}

// ResetAll clears all rate limit data.
func (l *Limiter) ResetAll() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.requests = make(map[string][]time.Time)
}

// Stop terminates the background cleanup goroutine.
// Call this when shutting down to prevent goroutine leaks.
func (l *Limiter) Stop() {
	close(l.stopChan)
}

// cleanup runs periodically to remove old entries and prevent memory leaks.
func (l *Limiter) cleanup() {
	ticker := time.NewTicker(l.window)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			l.cleanupOldEntries()
		case <-l.stopChan:
			return
		}
	}
}

func (l *Limiter) cleanupOldEntries() {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-l.window)

	for key, times := range l.requests {
		validTimes := make([]time.Time, 0)
		for _, t := range times {
			if t.After(cutoff) {
				validTimes = append(validTimes, t)
			}
		}

		if len(validTimes) == 0 {
			delete(l.requests, key)
		} else {
			l.requests[key] = validTimes
		}
	}
}
