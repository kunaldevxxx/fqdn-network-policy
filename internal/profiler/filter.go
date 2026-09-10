package profiler

import (
	"strings"

	netv1alpha1 "github.com/kunaldevxxx/fqdn-network-policy/api/v1alpha1"
)

var internalSuffixes = []string{
	".cluster.local",
	".cluster.local.",
	".svc",
	".svc.",
	".local",
	".local.",
	".internal",
	".internal.",
	".in-addr.arpa",
	".in-addr.arpa.",
	".ip6.arpa",
	".ip6.arpa.",
}

var exactInternalNames = map[string]struct{}{
	"kubernetes":               {},
	"kubernetes.default":       {},
	"kubernetes.default.svc":   {},
	"localhost":                {},
	"localhost.localdomain":    {},
	"ip6-localhost":            {},
	"ip6-loopback":             {},
	"metadata.google.internal": {},
	"169.254.169.254":          {},
}

// IsInternalDomain returns true if hostname is a Kubernetes cluster-internal
// service, localhost, or reverse-DNS pointer record that does not belong
// in an external egress policy.
func IsInternalDomain(hostname string) bool {
	hostname = strings.ToLower(strings.TrimSpace(hostname))
	if hostname == "" {
		return true
	}

	if _, ok := exactInternalNames[hostname]; ok {
		return true
	}

	for _, suffix := range internalSuffixes {
		if strings.HasSuffix(hostname, suffix) {
			return true
		}
	}

	// Single-label hostnames without any dot are internal/local (e.g. "coredns", "vault")
	trimmed := strings.TrimSuffix(hostname, ".")
	if !strings.Contains(trimmed, ".") {
		return true
	}

	return false
}

// FilterDomains partitions observed domains into external candidate domains
// and ignored internal/infrastructure domains.
func FilterDomains(domains []netv1alpha1.ObservedDomain) (external []netv1alpha1.ObservedDomain, internal []netv1alpha1.ObservedDomain) {
	for _, d := range domains {
		if IsInternalDomain(d.Hostname) {
			internal = append(internal, d)
		} else {
			external = append(external, d)
		}
	}
	return external, internal
}
