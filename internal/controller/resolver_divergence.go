package controller

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	netv1alpha1 "github.com/kunaldevxxx/fqdn-network-policy/api/v1alpha1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// blockOnDivergence reports whether sec opts into freezing NetworkPolicy
// application when resolvers disagree (Issue #4 follow-on). Defaults to
// false: divergent IPs are unioned in, as before this field existed.
func blockOnDivergence(sec *netv1alpha1.SecuritySpec) bool {
	return sec != nil && sec.BlockOnDivergence != nil && *sec.BlockOnDivergence
}

// anyDivergence reports whether any resolved host this cycle showed
// resolver disagreement.
func anyDivergence(resolved []netv1alpha1.ResolvedHost) bool {
	for _, h := range resolved {
		if h.Security != nil && h.Security.ResolverDivergence > 0 {
			return true
		}
	}
	return false
}

// divergenceMessage formats the per-hostname resolver-disagreement summary
// used on the ResolverDivergence condition, e.g. "api.stripe.com: 3
// resolvers returned 6 IPs total, 2 IPs appeared in only 1 resolver".
func divergenceMessage(resolved []netv1alpha1.ResolvedHost) string {
	var parts []string
	for _, h := range resolved {
		if h.Security == nil || h.Security.ResolverDivergence == 0 {
			continue
		}
		singleResolverIPs := 0
		for _, ip := range h.IPs {
			count := 0
			for _, ips := range h.Security.ResolverResults {
				if slices.Contains(ips, ip) {
					count++
				}
			}
			if count == 1 {
				singleResolverIPs++
			}
		}
		parts = append(parts, fmt.Sprintf("%s: %d resolvers returned %d IPs total, %d IPs appeared in only 1 resolver",
			h.Hostname, len(h.Security.ResolverResults), len(h.IPs), singleResolverIPs))
	}
	sort.Strings(parts)
	return strings.Join(parts, "; ")
}

// setResolverDivergenceCondition always sets the ResolverDivergence
// condition on fp -- True with a per-hostname summary when any resolved
// host disagreed across resolvers this cycle, False otherwise. Mirrors the
// always-present True/False pattern the existing Degraded condition uses.
func setResolverDivergenceCondition(fp *netv1alpha1.FQDNNetworkPolicy, resolved []netv1alpha1.ResolvedHost) {
	if anyDivergence(resolved) {
		setCondition(fp, "ResolverDivergence", metav1.ConditionTrue, "ResolverDisagreement", divergenceMessage(resolved))
		return
	}
	setCondition(fp, "ResolverDivergence", metav1.ConditionFalse, "NoDivergence", "")
}

// setClusterCondition upserts a condition on cp, mirroring setCondition's
// preserve-LastTransitionTime-when-unchanged behavior for the cluster-scoped type.
func setClusterCondition(cp *netv1alpha1.ClusterFQDNNetworkPolicy, condType string, status metav1.ConditionStatus, reason, msg string) {
	cond := metav1.Condition{
		Type:               condType,
		Status:             status,
		Reason:             reason,
		Message:            msg,
		ObservedGeneration: cp.Generation,
		LastTransitionTime: metav1.Now(),
	}
	for i, c := range cp.Status.Conditions {
		if c.Type == condType {
			if c.Status == status {
				cond.LastTransitionTime = c.LastTransitionTime
			}
			cp.Status.Conditions[i] = cond
			return
		}
	}
	cp.Status.Conditions = append(cp.Status.Conditions, cond)
}

// setClusterResolverDivergenceCondition is setResolverDivergenceCondition's
// ClusterFQDNNetworkPolicy counterpart.
func setClusterResolverDivergenceCondition(cp *netv1alpha1.ClusterFQDNNetworkPolicy, resolved []netv1alpha1.ResolvedHost) {
	if anyDivergence(resolved) {
		setClusterCondition(cp, "ResolverDivergence", metav1.ConditionTrue, "ResolverDisagreement", divergenceMessage(resolved))
		return
	}
	setClusterCondition(cp, "ResolverDivergence", metav1.ConditionFalse, "NoDivergence", "")
}
