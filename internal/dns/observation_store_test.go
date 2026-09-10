package dns_test

import (
	"testing"

	"github.com/kunaldevxxx/fqdn-network-policy/internal/dns"
	"github.com/stretchr/testify/assert"
)

func TestObservationStore_RecordAndAllDomains(t *testing.T) {
	o := dns.NewObservationStore()
	o.Record("api.stripe.com")
	o.Record("api.github.com")

	domains := o.AllDomains()
	assert.Len(t, domains, 2)
	assert.Contains(t, domains, "api.stripe.com")
	assert.Contains(t, domains, "api.github.com")
}

func TestObservationStore_AllDomains_EmptyWhenNothingRecorded(t *testing.T) {
	o := dns.NewObservationStore()
	assert.Empty(t, o.AllDomains())
}

func TestObservationStore_FirstSeenPreservedLastSeenAdvances(t *testing.T) {
	o := dns.NewObservationStore()
	o.Record("api.stripe.com")
	first := o.AllDomains()["api.stripe.com"].FirstSeen

	o.Record("api.stripe.com")
	second := o.AllDomains()["api.stripe.com"]

	assert.Equal(t, first, second.FirstSeen, "FirstSeen must not change on repeat observation")
	assert.False(t, second.LastSeen.Before(first), "LastSeen should not move backwards")
	assert.Equal(t, int64(2), second.QueryCount, "QueryCount must increment on repeat observation")
}

func TestObservationStore_QueryCountIncrements(t *testing.T) {
	o := dns.NewObservationStore()
	o.Record("api.stripe.com")
	o.Record("api.stripe.com")
	o.Record("api.stripe.com")

	assert.Equal(t, int64(3), o.AllDomains()["api.stripe.com"].QueryCount)
}
