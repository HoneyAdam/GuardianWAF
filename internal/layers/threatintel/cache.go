package threatintel

import (
	"container/list"
	"sync"
	"time"
)

// Cache is a thread-safe LRU cache with TTL support.
type Cache struct {
	capacity int
	ttl      time.Duration
	mu       sync.RWMutex
	entries  *list.List
	items    map[string]*list.Element
}

type cacheEntry struct {
	key       string
	value     *ThreatInfo
	expiresAt time.Time
}

// NewCache creates a new LRU cache with the given capacity and TTL.
func NewCache(capacity int, ttl time.Duration) *Cache {
	return &Cache{
		capacity: capacity,
		ttl:      ttl,
		entries:  list.New(),
		items:    make(map[string]*list.Element),
	}
}

// Get retrieves a value from the cache.
func (c *Cache) Get(key string) (*ThreatInfo, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, ok := c.items[key]; ok {
		entry := elem.Value.(*cacheEntry)
		// Check expiration
		if time.Now().After(entry.expiresAt) {
			c.entries.Remove(elem)
			delete(c.items, key)
			return nil, false
		}
		// Move to front (most recently used)
		c.entries.MoveToFront(elem)
		return entry.value, true
	}
	return nil, false
}

// Set adds a value to the cache.
func (c *Cache) Set(key string, value *ThreatInfo) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if already exists
	if elem, ok := c.items[key]; ok {
		entry := elem.Value.(*cacheEntry)
		entry.value = value
		entry.expiresAt = time.Now().Add(c.ttl)
		c.entries.MoveToFront(elem)
		return
	}

	// Add new entry
	entry := &cacheEntry{
		key:       key,
		value:     value,
		expiresAt: time.Now().Add(c.ttl),
	}
	elem := c.entries.PushFront(entry)
	c.items[key] = elem

	// Evict oldest if over capacity
	if c.capacity > 0 && c.entries.Len() > c.capacity {
		oldest := c.entries.Back()
		if oldest != nil {
			c.entries.Remove(oldest)
			delete(c.items, oldest.Value.(*cacheEntry).key)
		}
	}
}

// Delete removes a key from the cache.
func (c *Cache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, ok := c.items[key]; ok {
		c.entries.Remove(elem)
		delete(c.items, key)
	}
}

// Len returns the number of items in the cache.
func (c *Cache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.entries.Len()
}

// Clear removes all items from the cache.
func (c *Cache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = list.New()
	c.items = make(map[string]*list.Element)
}

// Cleanup removes expired entries from the cache.
func (c *Cache) Cleanup() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	count := 0
	for key, elem := range c.items {
		entry := elem.Value.(*cacheEntry)
		if now.After(entry.expiresAt) {
			c.entries.Remove(elem)
			delete(c.items, key)
			count++
		}
	}
	return count
}

// Keys returns all keys in the cache.
func (c *Cache) Keys() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	keys := make([]string, 0, len(c.items))
	for key := range c.items {
		keys = append(keys, key)
	}
	return keys
}
