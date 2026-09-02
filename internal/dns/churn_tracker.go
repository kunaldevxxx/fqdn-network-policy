package dns

import "sync"

const churnRingSize = 10

// ChurnTracker records per-hostname IP sets across resolution cycles and
// returns the count of distinct IPs seen in the last churnRingSize cycles.
// It is safe for concurrent use and must be created with NewChurnTracker.
type ChurnTracker struct {
	mu      sync.Mutex
	history map[string]*churnRing
}

// NewChurnTracker returns an initialised ChurnTracker.
func NewChurnTracker() *ChurnTracker {
	return &ChurnTracker{history: make(map[string]*churnRing)}
}

// Record adds the current IP set for hostname and returns the number of
// distinct IPs seen across the last churnRingSize cycles (including this one).
func (t *ChurnTracker) Record(hostname string, ips []string) int {
	t.mu.Lock()
	defer t.mu.Unlock()

	r, ok := t.history[hostname]
	if !ok {
		r = &churnRing{slots: make([]map[string]struct{}, churnRingSize)}
		t.history[hostname] = r
	}

	// Write current IP set into the next slot (overwriting the oldest).
	slot := make(map[string]struct{}, len(ips))
	for _, ip := range ips {
		slot[ip] = struct{}{}
	}
	r.slots[r.head] = slot
	r.head = (r.head + 1) % churnRingSize

	// Count distinct IPs across all populated slots.
	seen := make(map[string]struct{})
	for _, s := range r.slots {
		for ip := range s {
			seen[ip] = struct{}{}
		}
	}
	return len(seen)
}

type churnRing struct {
	slots []map[string]struct{}
	head  int
}
