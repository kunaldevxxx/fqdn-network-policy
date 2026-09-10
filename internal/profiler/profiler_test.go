package profiler_test

import (
	"testing"
	"time"

	netv1alpha1 "github.com/kunaldevxxx/fqdn-network-policy/api/v1alpha1"
	"github.com/kunaldevxxx/fqdn-network-policy/internal/profiler"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestFilterDomains(t *testing.T) {
	input := []netv1alpha1.ObservedDomain{
		{Hostname: "api.stripe.com"},
		{Hostname: "coredns.kube-system.svc.cluster.local"},
		{Hostname: "kubernetes.default.svc"},
		{Hostname: "1.2.3.4.in-addr.arpa"},
		{Hostname: "auth0.com"},
		{Hostname: "localhost"},
		{Hostname: "metadata.google.internal"},
	}

	external, internal := profiler.FilterDomains(input)

	assert.Len(t, external, 2)
	assert.Equal(t, "api.stripe.com", external[0].Hostname)
	assert.Equal(t, "auth0.com", external[1].Hostname)

	assert.Len(t, internal, 5)
}

func TestBaseDomain(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"api.stripe.com", "stripe.com"},
		{"checkout.stripe.com", "stripe.com"},
		{"m.checkout.stripe.com", "stripe.com"},
		{"stripe.com", "stripe.com"},
		{"api.service.co.uk", "service.co.uk"},
		{"auth.corp.com.au", "corp.com.au"},
		{"localhost", "localhost"},
	}

	for _, tt := range tests {
		assert.Equal(t, tt.expected, profiler.BaseDomain(tt.input))
	}
}

func TestClusterWildcards(t *testing.T) {
	domains := []string{
		"api.stripe.com",
		"m.stripe.com",
		"checkout.stripe.com",
		"api.github.com",
		"raw.githubusercontent.com",
	}

	// Threshold 3: stripe.com has 3 subdomains -> *.stripe.com
	res := profiler.ClusterWildcards(domains, 3)

	assert.Contains(t, res.Rules, "*.stripe.com")
	assert.Contains(t, res.Rules, "api.github.com")
	assert.Contains(t, res.Rules, "raw.githubusercontent.com")
	assert.NotContains(t, res.Rules, "api.stripe.com")
	assert.Len(t, res.WildcardClusters["*.stripe.com"], 3)

	// Threshold 0/1: no clustering
	noCluster := profiler.ClusterWildcards(domains, 0)
	assert.NotContains(t, noCluster.Rules, "*.stripe.com")
	assert.Contains(t, noCluster.Rules, "api.stripe.com")
	assert.Contains(t, noCluster.Rules, "checkout.stripe.com")
}

func TestClassifyDomain(t *testing.T) {
	tests := []struct {
		domain   string
		category string
		provider string
	}{
		{"api.stripe.com", "Payments & Financial", "Stripe"},
		{"s3.amazonaws.com", "Cloud & Storage", "AWS"},
		{"dev-123.us.auth0.com", "Auth & Identity", "Auth0"},
		{"app.datadoghq.com", "Observability & APM", "Datadog"},
		{"api.github.com", "Developer & Registries", "GitHub"},
		{"unknown-corp.io", "General / Unclassified", "unknown-corp.io"},
	}

	for _, tt := range tests {
		c := profiler.ClassifyDomain(tt.domain)
		assert.Equal(t, tt.category, c.Category)
		assert.Equal(t, tt.provider, c.Provider)
	}
}

func TestSynthesizePolicy(t *testing.T) {
	observed := []netv1alpha1.ObservedDomain{
		{Hostname: "api.stripe.com", QueryCount: 100},
		{Hostname: "checkout.stripe.com", QueryCount: 50},
		{Hostname: "m.stripe.com", QueryCount: 20},
		{Hostname: "api.github.com", QueryCount: 10},
		{Hostname: "internal.svc.cluster.local", QueryCount: 200}, // internal, should be dropped
	}

	opts := profiler.ProfileOptions{
		PolicyName:        "payments-egress",
		Namespace:         "production",
		PodSelector:       map[string]string{"app": "checkout"},
		WildcardThreshold: 3,
		Mode:              netv1alpha1.PolicyModeAudit,
		SecurityPreset:    "strict",
		ObservedDomains:   observed,
		ObservationSource: "test-observation",
	}

	policy, summary, err := profiler.SynthesizePolicy(opts)
	require.NoError(t, err)
	require.NotNil(t, policy)
	require.NotNil(t, summary)

	assert.Equal(t, "payments-egress", policy.Name)
	assert.Equal(t, "production", policy.Namespace)
	assert.Equal(t, netv1alpha1.PolicyModeAudit, policy.Spec.Mode)
	assert.Equal(t, "checkout", policy.Spec.PodSelector.PodSelector.MatchLabels["app"])

	// Security checks (strict preset)
	require.NotNil(t, policy.Spec.Security)
	assert.True(t, *policy.Spec.Security.BlockPrivateIPs)
	assert.True(t, *policy.Spec.Security.BlockOnDivergence)
	assert.Equal(t, int32(3), *policy.Spec.Security.MinResolverAgreement)

	// Summary checks
	assert.Equal(t, 5, summary.TotalObserved)
	assert.Equal(t, 1, summary.InternalIgnored)
	assert.Equal(t, 4, summary.ExternalAllowed)
	assert.Equal(t, 2, summary.RulesGenerated) // *.stripe.com and api.github.com
	assert.Equal(t, 1, summary.WildcardsGenerated)
}

func TestSimulate_CoverageAndBlastRadius(t *testing.T) {
	policy := &netv1alpha1.FQDNNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "checkout-policy", Namespace: "payments"},
		Spec: netv1alpha1.FQDNNetworkPolicySpec{
			Mode: netv1alpha1.PolicyModeEnforce,
			Egress: []netv1alpha1.FQDNRule{
				{Match: "*.stripe.com"},
				{Match: "api.github.com"},
			},
			Security: &netv1alpha1.SecuritySpec{
				BlockPrivateIPs: func() *bool { b := true; return &b }(),
			},
		},
	}

	now := time.Now()
	observed := []netv1alpha1.ObservedDomain{
		{Hostname: "api.stripe.com", QueryCount: 150, LastSeen: metav1.NewTime(now)},
		{Hostname: "files.stripe.com", QueryCount: 20, LastSeen: metav1.NewTime(now)},
		{Hostname: "api.github.com", QueryCount: 40, LastSeen: metav1.NewTime(now)},
		// Unpolicied external domains (The Blast Radius!)
		{Hostname: "telemetry.datadoghq.com", QueryCount: 300, LastSeen: metav1.NewTime(now)},
		{Hostname: "crl.identrust.com", QueryCount: 10, LastSeen: metav1.NewTime(now)},
		// Internal cluster service (Ignored)
		{Hostname: "postgres.payments.svc.cluster.local", QueryCount: 500, LastSeen: metav1.NewTime(now)},
	}

	report, err := profiler.Simulate(policy, observed)
	require.NoError(t, err)
	require.NotNil(t, report)

	assert.Equal(t, 6, report.TotalObserved)
	assert.Equal(t, 3, report.AllowedCount)  // api.stripe, files.stripe, api.github
	assert.Equal(t, 2, report.BlockedCount)  // datadog, identrust
	assert.Equal(t, 1, report.InternalCount) // postgres internal k8s

	assert.True(t, report.HasRisk)
	require.Len(t, report.BlockedDomains, 2)
	assert.Equal(t, "telemetry.datadoghq.com", report.BlockedDomains[0].Hostname)
	assert.Equal(t, "crl.identrust.com", report.BlockedDomains[1].Hostname)

	// Verify terminal report formatting doesn't panic and produces expected sections
	reportStr := report.String()
	assert.Contains(t, reportStr, "BLAST RADIUS REPORT")
	assert.Contains(t, reportStr, "telemetry.datadoghq.com")
	assert.Contains(t, reportStr, "BLOCKED (Blast Radius):  2")

	// Verify JSON export
	jsonBytes, err := report.JSON()
	require.NoError(t, err)
	assert.Contains(t, string(jsonBytes), `"blockedCount": 2`)
}
