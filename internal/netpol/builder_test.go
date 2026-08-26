package netpol_test

import (
	"testing"

	netv1alpha1 "github.com/kunaldevxxx/fqdn-network-policy/api/v1alpha1"
	"github.com/kunaldevxxx/fqdn-network-policy/internal/netpol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func newPolicy(hosts []netv1alpha1.ResolvedHost, egress []netv1alpha1.FQDNRule) *netv1alpha1.FQDNNetworkPolicy {
	return &netv1alpha1.FQDNNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Namespace: "default"},
		Spec: netv1alpha1.FQDNNetworkPolicySpec{
			PodSelector: netv1alpha1.PodSelectorSpec{
				PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "test"}},
			},
			Egress: egress,
			Mode:   netv1alpha1.PolicyModeEnforce,
		},
		Status: netv1alpha1.FQDNNetworkPolicyStatus{ResolvedHosts: hosts},
	}
}

func TestBuild_NoResolvedHosts_DenyAll(t *testing.T) {
	fp := newPolicy(nil, []netv1alpha1.FQDNRule{{Match: "api.example.com"}})
	np, err := netpol.Build(fp)
	require.NoError(t, err)
	// Should produce only the DNS allow rule when no hosts resolved.
	assert.Equal(t, 1, len(np.Spec.Egress), "deny-all mode: only DNS egress rule should exist")
	assert.Empty(t, np.Spec.Egress[0].To, "DNS rule has no To peers")
}

func TestBuild_WithResolvedIPv4(t *testing.T) {
	fp := newPolicy(
		[]netv1alpha1.ResolvedHost{{Hostname: "api.example.com", IPs: []string{"203.0.113.1", "203.0.113.2"}}},
		[]netv1alpha1.FQDNRule{{Match: "api.example.com", Ports: []netv1alpha1.PolicyPort{{Port: 443, Protocol: "TCP"}}}},
	)
	np, err := netpol.Build(fp)
	require.NoError(t, err)
	require.Equal(t, 2, len(np.Spec.Egress), "one FQDN rule + one DNS allow rule")

	cidrs := extractCIDRs(np.Spec.Egress[0])
	assert.Contains(t, cidrs, "203.0.113.1/32")
	assert.Contains(t, cidrs, "203.0.113.2/32")
}

func TestBuild_WithResolvedIPv6(t *testing.T) {
	fp := newPolicy(
		[]netv1alpha1.ResolvedHost{{Hostname: "v6.example.com", IPs: []string{"2001:db8::1"}}},
		[]netv1alpha1.FQDNRule{{Match: "v6.example.com"}},
	)
	np, err := netpol.Build(fp)
	require.NoError(t, err)
	cidrs := extractCIDRs(np.Spec.Egress[0])
	assert.Contains(t, cidrs, "2001:db8::1/128", "IPv6 addresses must use /128 host route")
}

func TestBuild_MixedDualStack(t *testing.T) {
	fp := newPolicy(
		[]netv1alpha1.ResolvedHost{{
			Hostname: "dual.example.com",
			IPs:      []string{"203.0.113.1", "2001:db8::1"},
		}},
		[]netv1alpha1.FQDNRule{{Match: "dual.example.com"}},
	)
	np, err := netpol.Build(fp)
	require.NoError(t, err)
	cidrs := extractCIDRs(np.Spec.Egress[0])
	assert.Contains(t, cidrs, "203.0.113.1/32")
	assert.Contains(t, cidrs, "2001:db8::1/128")
}

func TestBuild_DNSEgressAlwaysPresent(t *testing.T) {
	fp := newPolicy(
		[]netv1alpha1.ResolvedHost{{Hostname: "api.example.com", IPs: []string{"1.2.3.4"}}},
		[]netv1alpha1.FQDNRule{{Match: "api.example.com"}},
	)
	np, err := netpol.Build(fp)
	require.NoError(t, err)
	dnsRule := np.Spec.Egress[len(np.Spec.Egress)-1]
	ports := dnsRule.Ports
	require.Len(t, ports, 2, "DNS rule must allow both UDP/53 and TCP/53")

	protocols := make(map[string]bool)
	for _, p := range ports {
		assert.Equal(t, int32(53), p.Port.IntVal)
		protocols[string(*p.Protocol)] = true
	}
	assert.True(t, protocols["UDP"])
	assert.True(t, protocols["TCP"])
}

func TestBuild_PolicyType(t *testing.T) {
	fp := newPolicy(nil, []netv1alpha1.FQDNRule{{Match: "api.example.com"}})
	np, err := netpol.Build(fp)
	require.NoError(t, err)
	assert.Equal(t, []networkingv1.PolicyType{networkingv1.PolicyTypeEgress}, np.Spec.PolicyTypes)
}

func TestBuild_OwnerNameFormat(t *testing.T) {
	assert.Equal(t, "fqdnnp-my-policy", netpol.OwnerName("my-policy"))
}

func TestBuild_PodSelectorPropagated(t *testing.T) {
	fp := newPolicy(nil, []netv1alpha1.FQDNRule{{Match: "api.example.com"}})
	np, err := netpol.Build(fp)
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"app": "test"}, np.Spec.PodSelector.MatchLabels)
}

func extractCIDRs(rule networkingv1.NetworkPolicyEgressRule) []string {
	var cidrs []string
	for _, peer := range rule.To {
		if peer.IPBlock != nil {
			cidrs = append(cidrs, peer.IPBlock.CIDR)
		}
	}
	return cidrs
}
