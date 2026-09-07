package enrich

import (
	"sync"
	"time"
)

// cacheTTL is the maximum age of a cached enrichment before it is considered
// stale and re-fetched. This also serves as the per-IP rate limit: each IP
// is enriched at most once per this window.
const cacheTTL = 6 * time.Hour

type cacheEntry struct {
	result     Result
	enrichedAt time.Time
}

// cache is a thread-safe store of IP -> last known enrichment result.
// Mirrors the mutex/expiry style of dns.IPCache.
type cache struct {
	mu      sync.RWMutex
	entries map[string]cacheEntry
}

func newCache() *cache {
	return &cache{entries: make(map[string]cacheEntry)}
}

// Get returns the cached entry for ip regardless of freshness, and whether
// one exists at all.
func (c *cache) Get(ip string) (cacheEntry, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.entries[ip]
	return e, ok
}

// Fresh returns the cached entry for ip only if it was fetched within cacheTTL.
func (c *cache) Fresh(ip string) (cacheEntry, bool) {
	e, ok := c.Get(ip)
	if !ok || time.Since(e.enrichedAt) >= cacheTTL {
		return cacheEntry{}, false
	}
	return e, true
}

// Set records the enrichment result for ip, fetched now.
func (c *cache) Set(ip string, result Result) cacheEntry {
	e := cacheEntry{result: result, enrichedAt: time.Now()}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[ip] = e
	return e
}
