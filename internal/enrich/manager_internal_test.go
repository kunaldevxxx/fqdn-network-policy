package enrich

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/kunaldevxxx/fqdn-network-policy/internal/metrics"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubClient is a test double for Client with a configurable lookup function
// and a call counter.
type stubClient struct {
	calls  atomic.Int32
	lookup func(ip string) (Result, error)
}

func (s *stubClient) Lookup(_ context.Context, ip string) (Result, error) {
	s.calls.Add(1)
	return s.lookup(ip)
}

func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	require.Fail(t, "condition not met within timeout")
}

func TestManager_RequestAsync_PopulatesCacheWithoutBlocking(t *testing.T) {
	stub := &stubClient{lookup: func(ip string) (Result, error) {
		return Result{ASN: "AS111", Org: "Example Org", Country: "US"}, nil
	}}
	m := NewManager(stub, logr.Discard())
	defer m.Close()

	_, _, ok := m.Get("9.9.9.9")
	assert.False(t, ok, "Get before any lookup should report not-found, not block")

	m.RequestAsync("example.com", "9.9.9.9")

	waitFor(t, time.Second, func() bool {
		_, _, ok := m.Get("9.9.9.9")
		return ok
	})

	result, enrichedAt, ok := m.Get("9.9.9.9")
	require.True(t, ok)
	assert.Equal(t, "AS111", result.ASN)
	assert.Equal(t, "Example Org", result.Org)
	assert.WithinDuration(t, time.Now(), enrichedAt, time.Second)
}

func TestManager_RequestAsync_RateLimitedWithinCacheTTL(t *testing.T) {
	stub := &stubClient{lookup: func(ip string) (Result, error) {
		return Result{ASN: "AS111", Org: "Example Org"}, nil
	}}
	m := NewManager(stub, logr.Discard())
	defer m.Close()

	m.RequestAsync("example.com", "9.9.9.9")
	waitFor(t, time.Second, func() bool {
		_, _, ok := m.Get("9.9.9.9")
		return ok
	})

	// Fresh cache entry: further requests within cacheTTL must not re-fetch.
	for i := 0; i < 5; i++ {
		m.RequestAsync("example.com", "9.9.9.9")
	}
	time.Sleep(50 * time.Millisecond)
	assert.Equal(t, int32(1), stub.calls.Load(), "cached IP should be enriched at most once per cacheTTL window")
}

func TestManager_ASNChange_LogsAndIncrementsMetric(t *testing.T) {
	stub := &stubClient{lookup: func(ip string) (Result, error) {
		return Result{ASN: "AS100", Org: "First Org"}, nil
	}}
	m := NewManager(stub, logr.Discard())
	defer m.Close()

	before := testutil.ToFloat64(metrics.ASNChangeTotal.WithLabelValues("shifty.example.com", "AS100", "AS200"))

	// Directly exercise process() to simulate the ASN changing between
	// enrichment cycles without waiting out the real 6h cache TTL.
	m.process(enrichRequest{hostname: "shifty.example.com", ip: "8.8.4.4"})
	stub.lookup = func(ip string) (Result, error) {
		return Result{ASN: "AS200", Org: "Second Org"}, nil
	}
	m.process(enrichRequest{hostname: "shifty.example.com", ip: "8.8.4.4"})

	after := testutil.ToFloat64(metrics.ASNChangeTotal.WithLabelValues("shifty.example.com", "AS100", "AS200"))
	assert.Equal(t, before+1, after, "ASN change between cycles should increment fqdnnp_asn_change_total")

	result, _, ok := m.Get("8.8.4.4")
	require.True(t, ok)
	assert.Equal(t, "AS200", result.ASN, "cache should hold the latest enrichment")
}

func TestNewManagerFromConfig_DisabledByDefault(t *testing.T) {
	m, enabled := NewManagerFromConfig("", "", logr.Discard())
	assert.False(t, enabled)
	assert.Nil(t, m)

	m, enabled = NewManagerFromConfig("disabled", "", logr.Discard())
	assert.False(t, enabled)
	assert.Nil(t, m)
}

func TestNewManagerFromConfig_IPInfoEnablesManager(t *testing.T) {
	m, enabled := NewManagerFromConfig("ipinfo", "tok", logr.Discard())
	require.True(t, enabled)
	require.NotNil(t, m)
	defer m.Close()
}
