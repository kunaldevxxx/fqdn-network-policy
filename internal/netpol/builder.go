// Package netpol converts a resolved FQDNNetworkPolicy into a plain
// networking.k8s.io/v1 NetworkPolicy. Emitting a standard NetworkPolicy
// (rather than a CNI-specific CRD) is what makes this portable across
// Calico, AWS VPC CNI, Azure CNI, etc: enforcement stays with whatever
// the cluster already runs, this controller only manages IP sets.
package netpol

import (
	"fmt"

	netv1alpha1 "github.com/kunaldevxxx/fqdn-network-policy/api/v1alpha1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// OwnerName returns the deterministic name used for the generated
// NetworkPolicy, so reconciles are idempotent and easy to trace back
// to their source FQDNNetworkPolicy.
func OwnerName(fqdnPolicyName string) string {
	return fmt.Sprintf("fqdnnp-%s", fqdnPolicyName)
}

// Build produces the NetworkPolicy object for a given FQDNNetworkPolicy and
// its current resolution cache. Callers are expected to server-side-apply
// or create-or-update this object, not replace it wholesale, so that other
// fields (e.g. added by admission webhooks) aren't clobbered every loop.
func Build(fp *netv1alpha1.FQDNNetworkPolicy) (*networkingv1.NetworkPolicy, error) {
	if len(fp.Status.ResolvedHosts) == 0 {
		// No resolutions yet: emit a deny-all-egress-for-selected-pods policy
		// rather than an empty/no-op one. Silently allowing everything while
		// resolution warms up would defeat the point of the policy.
		return denyAllEgress(fp), nil
	}

	peers := make([]networkingv1.NetworkPolicyPeer, 0, len(fp.Status.ResolvedHosts))
	for _, host := range fp.Status.ResolvedHosts {
		for _, ip := range host.IPs {
			peers = append(peers, networkingv1.NetworkPolicyPeer{
				IPBlock: &networkingv1.IPBlock{CIDR: hostCIDR(ip)},
			})
		}
	}

	ports := collectPorts(fp)

	np := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      OwnerName(fp.Name),
			Namespace: fp.Namespace,
			Labels: map[string]string{
				"netsec.kunal.dev/managed-by":       "fqdn-network-policy",
				"netsec.kunal.dev/fqdnnetworkpolicy": fp.Name,
			},
			OwnerReferences: []metav1.OwnerReference{
				*metav1.NewControllerRef(fp, netv1alpha1.GroupVersion.WithKind("FQDNNetworkPolicy")),
			},
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels:      fp.Spec.PodSelector.PodSelector.MatchLabels,
				MatchExpressions: fp.Spec.PodSelector.PodSelector.MatchExpressions,
			},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
			Egress: []networkingv1.NetworkPolicyEgressRule{
				{
					To:    peers,
					Ports: ports,
				},
				// Always allow DNS egress (UDP/TCP 53) so resolution itself
				// keeps working; without this the policy can lock out the
				// very lookups it depends on to refresh.
				allowDNSRule(),
			},
		},
	}
	return np, nil
}

func denyAllEgress(fp *netv1alpha1.FQDNNetworkPolicy) *networkingv1.NetworkPolicy {
	return &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      OwnerName(fp.Name),
			Namespace: fp.Namespace,
			Labels: map[string]string{
				"netsec.kunal.dev/managed-by":       "fqdn-network-policy",
				"netsec.kunal.dev/fqdnnetworkpolicy": fp.Name,
			},
			OwnerReferences: []metav1.OwnerReference{
				*metav1.NewControllerRef(fp, netv1alpha1.GroupVersion.WithKind("FQDNNetworkPolicy")),
			},
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels:      fp.Spec.PodSelector.PodSelector.MatchLabels,
				MatchExpressions: fp.Spec.PodSelector.PodSelector.MatchExpressions,
			},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
			Egress:      []networkingv1.NetworkPolicyEgressRule{allowDNSRule()},
		},
	}
}

func allowDNSRule() networkingv1.NetworkPolicyEgressRule {
	udp := corev1Protocol("UDP")
	tcp := corev1Protocol("TCP")
	port53 := intstrPort(53)
	return networkingv1.NetworkPolicyEgressRule{
		Ports: []networkingv1.NetworkPolicyPort{
			{Protocol: &udp, Port: &port53},
			{Protocol: &tcp, Port: &port53},
		},
	}
}

func collectPorts(fp *netv1alpha1.FQDNNetworkPolicy) []networkingv1.NetworkPolicyPort {
	var ports []networkingv1.NetworkPolicyPort
	for _, rule := range fp.Spec.Egress {
		for _, p := range rule.Ports {
			proto := corev1Protocol(p.Protocol)
			port := intstrPort(p.Port)
			ports = append(ports, networkingv1.NetworkPolicyPort{
				Protocol: &proto,
				Port:     &port,
			})
		}
	}
	return ports // nil/empty means "all ports", matching NetworkPolicy semantics
}
