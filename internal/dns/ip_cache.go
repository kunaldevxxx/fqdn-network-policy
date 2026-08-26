package dns

import (
	"sync"
	"time"
)

// observedIP is one IP recorded for a hostname, with an expiry time.
type observedIP struct {
	ip      string
	expires time.Time
}

// IPCache is a thread-safe store of hostname → observed IPs built from
// live DNS traffic that the SnoopResolver intercepts. It is the shared
// data structure between the DNS proxy goroutine and the reconcile loop.
type IPCache struct {
	mu      sync.RWMutex
	entries map[string][]observedIP
}

func NewIPCache() *IPCache {
	return &IPCache{entries: make(map[string][]observedIP)}
}

// Record adds IPs for hostname, keeping them alive for ttl duration.
// Existing entries for the same hostname are merged and de-duplicated.
func (c *IPCache) Record(hostname string, ips []string, ttl time.Duration) {
	if ttl <= 0 {
		ttl = 60 * time.Second
	}
	expires := time.Now().Add(ttl)
	c.mu.Lock()
	defer c.mu.Unlock()

	existing := c.entries[hostname]
	merged := make(map[string]observedIP)
	for _, e := range existing {
		if time.Now().Before(e.expires) {
			merged[e.ip] = e
		}
	}
	for _, ip := range ips {
		merged[ip] = observedIP{ip: ip, expires: expires}
	}
	result := make([]observedIP, 0, len(merged))
	for _, e := range merged {
		result = append(result, e)
	}
	c.entries[hostname] = result
}

// Get returns the current live IPs for hostname (expired entries excluded).
// Returns nil when the hostname has never been observed or all entries expired.
func (c *IPCache) Get(hostname string) []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	entries := c.entries[hostname]
	now := time.Now()
	var live []string
	for _, e := range entries {
		if now.Before(e.expires) {
			live = append(live, e.ip)
		}
	}
	return live
}

// Len returns the number of tracked hostnames with at least one live entry.
func (c *IPCache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	now := time.Now()
	count := 0
	for _, entries := range c.entries {
		for _, e := range entries {
			if now.Before(e.expires) {
				count++
				break
			}
		}
	}
	return count
}
