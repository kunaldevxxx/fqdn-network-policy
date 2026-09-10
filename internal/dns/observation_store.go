package dns

import (
	"sync"
	"time"
)

// observationRetention is how long a hostname is kept after its last
// observation, to bound memory in ObservationStore.
const observationRetention = 48 * time.Hour

// pruneRetentionCheckInterval bounds how often pruneLocked does its full
// map scan, so a busy snoop resolver isn't scanning on every single query.
const pruneRetentionCheckInterval = 5 * time.Minute

// FirstLastSeen is the first/last observation time and query volume for one hostname.
type FirstLastSeen struct {
	FirstSeen  time.Time
	LastSeen   time.Time
	QueryCount int64
}

type domainObservation struct {
	firstSeen  time.Time
	lastSeen   time.Time
	queryCount int64
}

// ObservationStore records which hostnames the SnoopResolver has seen
// queried, and when. It backs the FQDNEgressObservation controller
// (Issue #8).
//
// This is cluster-wide, not per-pod or per-namespace: CoreDNS's forward
// plugin re-originates every forwarded query as its own client, so the
// source address the proxy sees on an incoming query is always CoreDNS's
// own pod IP, never the pod that originally asked. There is no way to
// recover the real client through a plain forward hop -- doing so would
// need either a custom CoreDNS build (the edns0 plugin, to carry the real
// client as an EDNS Client-Subnet option, which the standard
// registry.k8s.io/coredns/coredns image does not include) or a different
// interception mechanism entirely (eBPF/iptables at the source pod), both
// out of scope here. So this store intentionally has no per-source
// dimension: it tracks "hostname was queried" cluster-wide.
type ObservationStore struct {
	mu        sync.Mutex
	domains   map[string]*domainObservation
	lastPrune time.Time
}

// NewObservationStore returns an empty ObservationStore.
func NewObservationStore() *ObservationStore {
	return &ObservationStore{domains: make(map[string]*domainObservation)}
}

// Record notes that hostname was queried at the current time.
func (o *ObservationStore) Record(hostname string) {
	if hostname == "" {
		return
	}
	now := time.Now()
	o.mu.Lock()
	defer o.mu.Unlock()

	if obs, ok := o.domains[hostname]; ok {
		obs.lastSeen = now
		obs.queryCount++
	} else {
		o.domains[hostname] = &domainObservation{firstSeen: now, lastSeen: now, queryCount: 1}
	}
	o.pruneLocked()
}

// AllDomains returns every hostname observed cluster-wide, with first/last
// seen times and query counts.
func (o *ObservationStore) AllDomains() map[string]FirstLastSeen {
	o.mu.Lock()
	defer o.mu.Unlock()

	result := make(map[string]FirstLastSeen, len(o.domains))
	for hostname, obs := range o.domains {
		result[hostname] = FirstLastSeen{FirstSeen: obs.firstSeen, LastSeen: obs.lastSeen, QueryCount: obs.queryCount}
	}
	return result
}

// pruneLocked drops hostnames not observed in observationRetention.
// Callers must hold o.mu.
func (o *ObservationStore) pruneLocked() {
	now := time.Now()
	if now.Sub(o.lastPrune) < pruneRetentionCheckInterval {
		return
	}
	o.lastPrune = now
	cutoff := now.Add(-observationRetention)
	for hostname, obs := range o.domains {
		if obs.lastSeen.Before(cutoff) {
			delete(o.domains, hostname)
		}
	}
}
