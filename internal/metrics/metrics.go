// Package metrics registers all Prometheus instrumentation for the FQDN controller.
// Follows the same naming convention as Cilium (cilium_*) and Istio (istio_*):
// all metrics are prefixed fqdn_*.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

// DNS resolution metrics
var (
	DNSLookupDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "fqdn_dns_lookup_duration_seconds",
			Help:    "Latency of DNS lookups by resolver type and domain.",
			Buckets: []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1, 2.5},
		},
		[]string{"domain", "resolver"},
	)

	DNSLookupFailures = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "fqdn_dns_lookup_failures_total",
			Help: "Total DNS lookup failures partitioned by domain and error type (nxdomain, timeout, servfail, other).",
		},
		[]string{"domain", "error_type"},
	)

	DNSCacheHits = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "fqdn_dns_cache_hits_total",
			Help: "Total DNS resolution requests served from the snoop IP cache without a network round-trip.",
		},
		[]string{"domain"},
	)

	SnoopObservations = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "fqdn_dns_snoop_observations_total",
			Help: "Total DNS responses intercepted by the SnoopResolver proxy, partitioned by query type (A, AAAA).",
		},
		[]string{"qtype"},
	)

	TTLExpiryLag = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "fqdn_ttl_expiry_lag_seconds",
			Help:    "How many seconds after TTL expiry the reconciler re-resolved a domain. High values indicate scheduling latency.",
			Buckets: []float64{0, 1, 5, 10, 30, 60, 120, 300},
		},
		[]string{"domain"},
	)

	WildcardExpansions = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "fqdn_wildcard_expansions_total",
			Help: "Wildcard FQDN expansions attempted, partitioned by outcome (success, partial, failed).",
		},
		[]string{"outcome"},
	)
)

// IP set & NetworkPolicy metrics
var (
	ResolvedIPsCount = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "fqdn_resolved_ips_count",
			Help: "Current number of IPs resolved per domain (gauge; drops when IPs expire).",
		},
		[]string{"domain"},
	)

	IPChangesTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "fqdn_ip_changes_total",
			Help: "Number of times the resolved IP set for a domain changed, triggering a NetworkPolicy update.",
		},
		[]string{"domain"},
	)

	NetworkPolicySyncDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "fqdn_networkpolicy_sync_duration_seconds",
			Help:    "Time taken to apply (create or update) a NetworkPolicy to the Kubernetes API server.",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"operation"}, // create, update, skip
	)

	NetworkPolicySyncErrors = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "fqdn_networkpolicy_sync_errors_total",
			Help: "Total NetworkPolicy sync failures partitioned by error type.",
		},
		[]string{"error_type"},
	)
)

// Controller lifecycle metrics
var (
	ManagedPolicies = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "fqdn_managed_policies_total",
			Help: "Number of FQDNNetworkPolicy objects currently being reconciled.",
		},
	)

	ClusterManagedNamespaces = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "fqdn_cluster_managed_namespaces_total",
			Help: "Number of namespaces currently receiving NetworkPolicies from ClusterFQDNNetworkPolicies.",
		},
	)

	ReconcileDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "fqdn_reconcile_duration_seconds",
			Help:    "End-to-end time for one reconcile loop (DNS + NetworkPolicy sync).",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"controller"}, // fqdnnetworkpolicy, clusterfqdnnetworkpolicy
	)

	LeaderTransitions = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "fqdn_leader_transitions_total",
			Help: "Number of leader election transitions this instance has observed (both gained and lost).",
		},
	)

	SnoopCacheSize = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "fqdn_snoop_cache_size",
			Help: "Number of active hostname entries in the SnoopResolver IP cache.",
		},
	)
)

func init() {
	metrics.Registry.MustRegister(
		// DNS
		DNSLookupDuration,
		DNSLookupFailures,
		DNSCacheHits,
		SnoopObservations,
		TTLExpiryLag,
		WildcardExpansions,
		// IP / NetworkPolicy
		ResolvedIPsCount,
		IPChangesTotal,
		NetworkPolicySyncDuration,
		NetworkPolicySyncErrors,
		// Controller
		ManagedPolicies,
		ClusterManagedNamespaces,
		ReconcileDuration,
		LeaderTransitions,
		SnoopCacheSize,
	)
}
