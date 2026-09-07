package controller

import (
	netv1alpha1 "github.com/kunaldevxxx/fqdn-network-policy/api/v1alpha1"
	"github.com/kunaldevxxx/fqdn-network-policy/internal/enrich"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// buildIPEnrichments requests (async, non-blocking) enrichment for every IP
// and returns whatever is already cached, keyed by IP. Returns nil when
// enricher is nil (ASN enricher not configured) or nothing is cached yet.
func buildIPEnrichments(enricher *enrich.Manager, hostname string, ips []string) map[string]netv1alpha1.IPEnrichment {
	if enricher == nil {
		return nil
	}

	var enrichments map[string]netv1alpha1.IPEnrichment
	for _, ip := range ips {
		enricher.RequestAsync(hostname, ip)
		result, enrichedAt, ok := enricher.Get(ip)
		if !ok || (result.ASN == "" && result.Org == "" && result.Country == "") {
			// Either not enriched yet, or the enricher had no ASN/org/country
			// data for this IP (e.g. a NAT64-synthesized address) -- an empty
			// record would only clutter status with nothing learned.
			continue
		}
		if enrichments == nil {
			enrichments = make(map[string]netv1alpha1.IPEnrichment, len(ips))
		}
		at := metav1.NewTime(enrichedAt)
		enrichments[ip] = netv1alpha1.IPEnrichment{
			ASN:        result.ASN,
			Org:        result.Org,
			Country:    result.Country,
			EnrichedAt: &at,
		}
	}
	return enrichments
}
