package sso

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Cache is a generic key-value storage interface for sessions, state, tokens, and JWKS.
type Cache interface {
	Get(ctx context.Context, key string) ([]byte, bool, error)
	Set(ctx context.Context, key string, val []byte, ttl time.Duration) error
	Delete(ctx context.Context, key string) error
	Clear(ctx context.Context) error
}

type cacheItem struct {
	val       []byte
	expiresAt time.Time
}

// MemoryCache is a high-performance thread-safe in-memory cache with TTL expiration.
type MemoryCache struct {
	mu    sync.RWMutex
	items map[string]cacheItem
}

// NewMemoryCache initializes an in-memory cache and starts an eviction worker.
func NewMemoryCache(cleanupInterval time.Duration) *MemoryCache {
	c := &MemoryCache{
		items: make(map[string]cacheItem),
	}
	if cleanupInterval > 0 {
		go c.startEviction(cleanupInterval)
	}
	return c
}

func (c *MemoryCache) Get(ctx context.Context, key string) ([]byte, bool, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	item, found := c.items[key]
	if !found {
		return nil, false, nil
	}
	if !item.expiresAt.IsZero() && time.Now().After(item.expiresAt) {
		return nil, false, nil
	}

	// Return a copy of bytes to ensure immutability
	res := make([]byte, len(item.val))
	copy(res, item.val)
	return res, true, nil
}

func (c *MemoryCache) Set(ctx context.Context, key string, val []byte, ttl time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	var exp time.Time
	if ttl > 0 {
		exp = time.Now().Add(ttl)
	}

	cpy := make([]byte, len(val))
	copy(cpy, val)
	c.items[key] = cacheItem{
		val:       cpy,
		expiresAt: exp,
	}
	return nil
}

func (c *MemoryCache) Delete(ctx context.Context, key string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.items, key)
	return nil
}

func (c *MemoryCache) Clear(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items = make(map[string]cacheItem)
	return nil
}

func (c *MemoryCache) startEviction(interval time.Duration) {
	ticker := time.NewTicker(interval)
	for range ticker.C {
		c.mu.Lock()
		now := time.Now()
		for k, v := range c.items {
			if !v.expiresAt.IsZero() && now.After(v.expiresAt) {
				delete(c.items, k)
			}
		}
		c.mu.Unlock()
	}
}

// MemoryCache test verification
var _ Cache = (*MemoryCache)(nil)

// Key helper
func CacheKey(prefix, id string) string {
	return fmt.Sprintf("%s:%s", prefix, id)
}
