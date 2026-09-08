package controller

import (
	"context"
	"sort"
	"strings"

	netv1alpha1 "github.com/kunaldevxxx/fqdn-network-policy/api/v1alpha1"
	"github.com/kunaldevxxx/fqdn-network-policy/internal/dns"
	"github.com/kunaldevxxx/fqdn-network-policy/internal/metrics"

	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// matchesEgressRule reports whether hostname is covered by an FQDNRule's
// Match value, supporting the same "*.suffix" wildcard shorthand FQDNRule
// documents.
func matchesEgressRule(hostname, match string) bool {
	if hostname == match {
		return true
	}
	if suffix, ok := strings.CutPrefix(match, "*."); ok {
		return strings.HasSuffix(hostname, "."+suffix) || hostname == suffix
	}
	return false
}

// computeUnpoliciedDomains diffs the snoop resolver's cluster-wide observed
// hostnames against the union of every FQDNNetworkPolicy's egress rules in
// namespace, returning the hostnames not covered by any of them.
//
// This is namespace-scoped only in which policies it diffs against -- the
// observation input itself remains cluster-wide, since SnoopResolver has no
// way to attribute a DNS query to its source pod or namespace (see
// internal/dns/observation_store.go's doc comment for why).
func computeUnpoliciedDomains(
	ctx context.Context, c client.Client, namespace string, snoop *dns.SnoopResolver,
) ([]netv1alpha1.ObservedDomain, error) {
	var policies netv1alpha1.FQDNNetworkPolicyList
	if err := c.List(ctx, &policies, client.InNamespace(namespace)); err != nil {
		return nil, err
	}

	var covered []string
	for _, p := range policies.Items {
		for _, rule := range p.Spec.Egress {
			covered = append(covered, rule.Match)
		}
	}

	observed := snoop.Observations().AllDomains()
	hostnames := make([]string, 0, len(observed))
	for hostname := range observed {
		hostnames = append(hostnames, hostname)
	}
	sort.Strings(hostnames)

	var drift []netv1alpha1.ObservedDomain
	for _, hostname := range hostnames {
		if isCovered(hostname, covered) {
			continue
		}
		seen := observed[hostname]
		drift = append(drift, netv1alpha1.ObservedDomain{
			Hostname:  hostname,
			FirstSeen: metav1.NewTime(seen.FirstSeen),
			LastSeen:  metav1.NewTime(seen.LastSeen),
		})
	}
	return drift, nil
}

func isCovered(hostname string, matches []string) bool {
	for _, match := range matches {
		if matchesEgressRule(hostname, match) {
			return true
		}
	}
	return false
}

// diffNewDomains returns the hostnames present in current but absent from
// previous, so callers can log/count drift once per newly-detected domain
// rather than on every reconcile while it remains undetected.
func diffNewDomains(previous, current []netv1alpha1.ObservedDomain) []string {
	prevSet := make(map[string]struct{}, len(previous))
	for _, d := range previous {
		prevSet[d.Hostname] = struct{}{}
	}
	var newOnes []string
	for _, d := range current {
		if _, ok := prevSet[d.Hostname]; !ok {
			newOnes = append(newOnes, d.Hostname)
		}
	}
	return newOnes
}

// recordDrift populates fp.Status.ObservedUnpoliciedDomains (Issue #6) when
// the snoop resolver is active. A nil Snoop is a no-op: the field is left
// exactly as it was, so there's no behavior change without the snoop
// resolver enabled.
//
// The diff is recomputed fresh every call, not accumulated, so it clears
// automatically once a covering policy exists.
//
// Known limitation: this can log/count a single newly-drifting domain more
// than once. The comparison is "not in the status this reconcile started
// with" -- so two reconciles of the same object that both read a status
// snapshot from before either one's write has landed (e.g. a short-TTL
// hostname re-reconciling every few seconds right as new drift appears, or
// two FQDNNetworkPolicy objects in the same namespace computing the same
// diff independently) can both see the domain as "new." Confirmed in
// practice via demo.sh: a fast re-reconcile of a short-TTL host logged the
// same newly-drifted domain twice in one run. Not worth a shared
// per-namespace/per-object dedup store for a signal whose job is "this is
// happening," not exact-once counting.
func (r *FQDNNetworkPolicyReconciler) recordDrift(ctx context.Context, fp *netv1alpha1.FQDNNetworkPolicy, logger logr.Logger) {
	if r.Snoop == nil {
		return
	}
	drift, err := computeUnpoliciedDomains(ctx, r.Client, fp.Namespace, r.Snoop)
	if err != nil {
		logger.Error(err, "computing egress drift failed", "namespace", fp.Namespace)
		return
	}
	for _, hostname := range diffNewDomains(fp.Status.ObservedUnpoliciedDomains, drift) {
		logger.Info("egress drift detected", "namespace", fp.Namespace, "domain", hostname)
		metrics.UnpoliciedDomainTotal.WithLabelValues(fp.Namespace, hostname).Inc()
	}
	fp.Status.ObservedUnpoliciedDomains = drift
}
