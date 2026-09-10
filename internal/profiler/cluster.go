package profiler

import (
	"sort"
	"strings"
)

var commonMultiPartTLDs = map[string]struct{}{
	"co.uk":  {},
	"org.uk": {},
	"gov.uk": {},
	"ac.uk":  {},
	"co.jp":  {},
	"ne.jp":  {},
	"com.au": {},
	"net.au": {},
	"org.au": {},
	"co.nz":  {},
	"co.in":  {},
	"net.in": {},
	"org.in": {},
	"gen.in": {},
	"ind.in": {},
}

// BaseDomain extracts the registrable base domain from an FQDN,
// correctly accounting for common two-part public suffixes (e.g. .co.uk).
// Examples:
//
//	api.stripe.com -> stripe.com
//	files.checkout.stripe.com -> stripe.com
//	api.service.co.uk -> service.co.uk
func BaseDomain(hostname string) string {
	hostname = strings.ToLower(strings.TrimSpace(hostname))
	hostname = strings.TrimSuffix(hostname, ".")
	parts := strings.Split(hostname, ".")
	if len(parts) <= 2 {
		return hostname
	}

	lastTwo := parts[len(parts)-2] + "." + parts[len(parts)-1]
	if _, ok := commonMultiPartTLDs[lastTwo]; ok {
		if len(parts) >= 3 {
			return parts[len(parts)-3] + "." + lastTwo
		}
		return hostname
	}

	return parts[len(parts)-2] + "." + parts[len(parts)-1]
}

// ClusterResult contains the synthesized match rules and the mappings of
// any subdomains that were clustered into wildcards.
type ClusterResult struct {
	// Rules is the deduplicated, sorted list of FQDN match rules (exact or wildcard).
	Rules []string
	// WildcardClusters maps each generated wildcard rule (e.g. "*.stripe.com")
	// to the specific subdomains that triggered or were merged into it.
	WildcardClusters map[string][]string
}

// ClusterWildcards groups subdomains by their base domain. If the number of
// distinct subdomains under a base domain reaches or exceeds threshold,
// they are clustered into a "*.basedomain" wildcard rule. If threshold <= 1,
// no automatic clustering is performed unless explicitly already a wildcard.
func ClusterWildcards(domains []string, threshold int) ClusterResult {
	if threshold <= 1 {
		// Keep exact hostnames, deduplicated and sorted
		unique := make(map[string]struct{}, len(domains))
		for _, d := range domains {
			d = strings.ToLower(strings.TrimSpace(d))
			d = strings.TrimSuffix(d, ".")
			if d != "" {
				unique[d] = struct{}{}
			}
		}
		rules := make([]string, 0, len(unique))
		for d := range unique {
			rules = append(rules, d)
		}
		sort.Strings(rules)
		return ClusterResult{
			Rules:            rules,
			WildcardClusters: make(map[string][]string),
		}
	}

	byBase := make(map[string][]string)
	for _, raw := range domains {
		d := strings.ToLower(strings.TrimSpace(raw))
		d = strings.TrimSuffix(d, ".")
		if d == "" {
			continue
		}
		base := BaseDomain(d)
		byBase[base] = append(byBase[base], d)
	}

	var rules []string
	clusters := make(map[string][]string)

	for base, subs := range byBase {
		// Deduplicate subdomains under this base
		uniqueSubs := make(map[string]struct{}, len(subs))
		for _, s := range subs {
			uniqueSubs[s] = struct{}{}
		}

		subList := make([]string, 0, len(uniqueSubs))
		for s := range uniqueSubs {
			subList = append(subList, s)
		}
		sort.Strings(subList)

		// Check if any sub is already a wildcard or if count meets threshold
		hasExplicitWildcard := false
		for _, s := range subList {
			if strings.HasPrefix(s, "*.") {
				hasExplicitWildcard = true
				break
			}
		}

		if hasExplicitWildcard || len(subList) >= threshold {
			wildcard := "*." + base
			rules = append(rules, wildcard)
			clusters[wildcard] = subList
		} else {
			rules = append(rules, subList...)
		}
	}

	sort.Strings(rules)
	return ClusterResult{
		Rules:            rules,
		WildcardClusters: clusters,
	}
}
