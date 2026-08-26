package dns_test

import (
	"context"
	"regexp"
	"testing"
	"time"

	"github.com/kunaldevxxx/fqdn-network-policy/internal/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── IPCache ────────────────────────────────────────────────────────────────

func TestIPCache_RecordAndGet(t *testing.T) {
	c := dns.NewIPCache()
	c.Record("api.example.com", []string{"1.2.3.4", "1.2.3.5"}, 60*time.Second)
	got := c.Get("api.example.com")
	assert.ElementsMatch(t, []string{"1.2.3.4", "1.2.3.5"}, got)
}

func TestIPCache_MergesEntries(t *testing.T) {
	c := dns.NewIPCache()
	c.Record("api.example.com", []string{"1.2.3.4"}, 60*time.Second)
	c.Record("api.example.com", []string{"5.6.7.8"}, 60*time.Second)
	assert.ElementsMatch(t, []string{"1.2.3.4", "5.6.7.8"}, c.Get("api.example.com"),
		"second Record should merge, not replace")
}

func TestIPCache_ExpiredEntriesExcluded(t *testing.T) {
	c := dns.NewIPCache()
	c.Record("api.example.com", []string{"1.2.3.4"}, 1*time.Millisecond)
	time.Sleep(5 * time.Millisecond)
	assert.Empty(t, c.Get("api.example.com"), "expired IPs should not be returned")
}

func TestIPCache_MissReturnsNil(t *testing.T) {
	assert.Nil(t, dns.NewIPCache().Get("never-seen.example.com"))
}

func TestIPCache_Len(t *testing.T) {
	c := dns.NewIPCache()
	assert.Equal(t, 0, c.Len())
	c.Record("a.example.com", []string{"1.1.1.1"}, 60*time.Second)
	c.Record("b.example.com", []string{"2.2.2.2"}, 60*time.Second)
	assert.Equal(t, 2, c.Len())
}

// ── TTLQueue ───────────────────────────────────────────────────────────────

func TestTTLQueue_UpsertAndMinDelay(t *testing.T) {
	q := dns.NewTTLQueue()
	q.Upsert("a.example.com", 10*time.Second)
	q.Upsert("b.example.com", 30*time.Second)
	delay := q.MinDelay(5 * time.Second)
	assert.GreaterOrEqual(t, delay, 8*time.Second, "min delay should be close to 10s")
	assert.LessOrEqual(t, delay, 11*time.Second)
}

func TestTTLQueue_UpsertUpdatesEntry(t *testing.T) {
	q := dns.NewTTLQueue()
	q.Upsert("a.example.com", 60*time.Second)
	q.Upsert("a.example.com", 5*time.Second)
	assert.LessOrEqual(t, q.MinDelay(1*time.Second), 6*time.Second,
		"upserting shorter TTL should lower the min delay")
}

func TestTTLQueue_EmptyReturnsFloor(t *testing.T) {
	q := dns.NewTTLQueue()
	floor := 45 * time.Second
	assert.Equal(t, floor, q.MinDelay(floor))
}

// ── ActiveResolver (network) ───────────────────────────────────────────────

func TestActiveResolver_ResolvesPublicDomain(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in -short mode")
	}
	r := dns.NewActiveResolver()
	res, err := r.Resolve(context.Background(), "one.one.one.one")
	require.NoError(t, err)
	assert.NotEmpty(t, res.IPs)
	assert.Greater(t, res.TTL, time.Duration(0))
}

func TestActiveResolver_NXDOMAINReturnsError(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in -short mode")
	}
	r := dns.NewActiveResolver()
	_, err := r.Resolve(context.Background(), "this.domain.absolutely.does.not.exist.example.invalid")
	assert.Error(t, err)
}

func TestActiveResolver_EmptyHostnameReturnsError(t *testing.T) {
	r := dns.NewActiveResolver()
	_, err := r.Resolve(context.Background(), "")
	assert.Error(t, err)
}

// ── WildcardResolver ───────────────────────────────────────────────────────

func TestWildcardResolver_PlainFQDNDelegates(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in -short mode")
	}
	wr := dns.NewWildcardResolver(dns.NewMultiResolver(nil), nil)
	res, err := wr.Resolve(context.Background(), "one.one.one.one")
	require.NoError(t, err)
	assert.NotEmpty(t, res.IPs)
}

func TestWildcardResolver_LearnPrefix(t *testing.T) {
	wr := dns.NewWildcardResolver(dns.NewMultiResolver(nil), nil)
	// Should not panic and should store the prefix for future expansions.
	wr.LearnPrefix("example.com", "custom-api")
	wr.LearnPrefix("example.com", "custom-api") // idempotent
}

// ── FQDN validation logic (mirrored from webhook to avoid import cycle) ────

var testFQDNRE = regexp.MustCompile(`^(\*\.)?([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)

func isValidFQDN(s string) bool { return testFQDNRE.MatchString(s) }

func TestFQDNValidation(t *testing.T) {
	cases := []struct {
		input string
		valid bool
	}{
		{"api.stripe.com", true},
		{"*.googleapis.com", true},
		{"storage.us-east-1.amazonaws.com", true},
		{"a.b.c.d.example.co.uk", true},
		{"not a domain", false},
		{"192.168.1.1", false},
		{"-bad.example.com", false},
		{"", false},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			assert.Equal(t, tc.valid, isValidFQDN(tc.input))
		})
	}
}
