package enrich

import (
	"context"
	"time"

	"github.com/go-logr/logr"

	"github.com/kunaldevxxx/fqdn-network-policy/internal/metrics"
)

const (
	enrichWorkers  = 4
	enrichQueueLen = 256
	lookupTimeout  = 5 * time.Second
)

type enrichRequest struct {
	hostname string
	ip       string
}

// Manager runs ASN/org enrichment asynchronously in the background so the
// reconcile loop is never blocked on a network call. Reconcilers call
// RequestAsync to (maybe) trigger a background fetch, and Get to read
// whatever is already cached -- both are non-blocking, map-only operations.
type Manager struct {
	client Client
	cache  *cache
	logger logr.Logger

	queue chan enrichRequest
	done  chan struct{}
}

// NewManager starts a Manager with a small fixed worker pool. Call Close to
// stop the workers (e.g. on manager shutdown, or in tests).
func NewManager(client Client, logger logr.Logger) *Manager {
	m := &Manager{
		client: client,
		cache:  newCache(),
		logger: logger,
		queue:  make(chan enrichRequest, enrichQueueLen),
		done:   make(chan struct{}),
	}
	for i := 0; i < enrichWorkers; i++ {
		go m.worker()
	}
	return m
}

// NewManagerFromConfig builds a Manager from the controller's ASN-enricher
// configuration (sourced from the FQDNNP_ASN_ENRICHER / FQDNNP_IPINFO_TOKEN
// env vars, or their equivalent manager flags). Returns (nil, false) when
// enricherMode is not "ipinfo" -- the enricher is opt-in and disabled by
// default, making zero external calls.
func NewManagerFromConfig(enricherMode, ipinfoToken string, logger logr.Logger) (*Manager, bool) {
	if enricherMode != "ipinfo" {
		return nil, false
	}
	return NewManager(NewIPInfoClient(ipinfoToken), logger), true
}

// Get returns the last known enrichment for ip, however stale, and whether
// one has ever been fetched. It never performs I/O.
func (m *Manager) Get(ip string) (Result, time.Time, bool) {
	e, ok := m.cache.Get(ip)
	if !ok {
		return Result{}, time.Time{}, false
	}
	return e.result, e.enrichedAt, true
}

// RequestAsync (maybe) enqueues a background enrichment fetch for ip and
// returns immediately. It is a no-op when the cached entry for ip is still
// fresh (rate limit: at most one fetch per IP per cacheTTL) or when the
// queue is full (best-effort; a later reconcile cycle will retry).
func (m *Manager) RequestAsync(hostname, ip string) {
	if _, fresh := m.cache.Fresh(ip); fresh {
		return
	}
	select {
	case m.queue <- enrichRequest{hostname: hostname, ip: ip}:
	default:
		// Queue full; drop and let the next reconcile cycle retry.
	}
}

// Close stops the worker pool. Safe to call once.
func (m *Manager) Close() {
	close(m.done)
}

func (m *Manager) worker() {
	for {
		select {
		case <-m.done:
			return
		case req := <-m.queue:
			m.process(req)
		}
	}
}

func (m *Manager) process(req enrichRequest) {
	ctx, cancel := context.WithTimeout(context.Background(), lookupTimeout)
	defer cancel()

	result, err := m.client.Lookup(ctx, req.ip)
	if err != nil {
		m.logger.Error(err, "ASN enrichment lookup failed", "hostname", req.hostname, "ip", req.ip)
		return
	}

	prev, hadPrev := m.cache.Get(req.ip)
	m.cache.Set(req.ip, result)

	if hadPrev && prev.result.ASN != "" && result.ASN != "" && prev.result.ASN != result.ASN {
		m.logger.Info("WARNING: resolved IP's ASN/org changed between enrichment cycles",
			"hostname", req.hostname, "ip", req.ip,
			"previousASN", prev.result.ASN, "currentASN", result.ASN,
			"previousOrg", prev.result.Org, "currentOrg", result.Org)
		metrics.ASNChangeTotal.WithLabelValues(req.hostname, prev.result.ASN, result.ASN).Inc()
	}
}
