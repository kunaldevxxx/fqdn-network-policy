package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	netv1alpha1 "github.com/kunaldevxxx/fqdn-network-policy/api/v1alpha1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"
)

func TestProfileCmd_OfflineFile(t *testing.T) {
	tempDir := t.TempDir()
	obsFile := filepath.Join(tempDir, "observation.yaml")
	outFile := filepath.Join(tempDir, "policy.yaml")

	now := metav1.NewTime(time.Now())
	obs := netv1alpha1.FQDNEgressObservation{
		TypeMeta: metav1.TypeMeta{
			APIVersion: netv1alpha1.GroupVersion.String(),
			Kind:       "FQDNEgressObservation",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "checkout-obs",
			Namespace: "payments",
		},
		Spec: netv1alpha1.FQDNEgressObservationSpec{
			PodSelector: netv1alpha1.PodSelectorSpec{
				PodSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{"app": "checkout-service"},
				},
			},
		},
		Status: netv1alpha1.FQDNEgressObservationStatus{
			ObservedDomains: []netv1alpha1.ObservedDomain{
				// Stripe subdomains (should cluster into *.stripe.com with threshold 3)
				{Hostname: "api.stripe.com", FirstSeen: now, LastSeen: now, QueryCount: 100},
				{Hostname: "checkout.stripe.com", FirstSeen: now, LastSeen: now, QueryCount: 50},
				{Hostname: "m.stripe.com", FirstSeen: now, LastSeen: now, QueryCount: 20},
				// GitHub (only 1 subdomain, should remain explicit)
				{Hostname: "api.github.com", FirstSeen: now, LastSeen: now, QueryCount: 15},
				// Auth0 (only 1, explicit)
				{Hostname: "login.auth0.com", FirstSeen: now, LastSeen: now, QueryCount: 30},
				// Internal cluster domains (should be filtered out)
				{Hostname: "coredns.kube-system.svc.cluster.local", FirstSeen: now, LastSeen: now, QueryCount: 500},
				{Hostname: "kubernetes.default.svc", FirstSeen: now, LastSeen: now, QueryCount: 200},
				{Hostname: "localhost", FirstSeen: now, LastSeen: now, QueryCount: 10},
			},
		},
	}

	data, err := yaml.Marshal(obs)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(obsFile, data, 0644))

	// Reset global flags before running
	profileFromFile = obsFile
	profileOutput = outFile
	profileWildcardThresh = 3
	profilePreset = "strict"
	profileAppLabel = "app=checkout"
	profileMode = "Audit"
	profileName = "checkout-egress"
	namespace = "payments"

	err = runProfile(nil, nil)
	require.NoError(t, err)

	// Verify generated policy file
	generatedData, err := os.ReadFile(outFile)
	require.NoError(t, err)

	var policy netv1alpha1.FQDNNetworkPolicy
	require.NoError(t, yaml.Unmarshal(generatedData, &policy))

	assert.Equal(t, "checkout-egress", policy.Name)
	assert.Equal(t, "payments", policy.Namespace)
	assert.Equal(t, netv1alpha1.PolicyModeAudit, policy.Spec.Mode)
	assert.Equal(t, "checkout", policy.Spec.PodSelector.PodSelector.MatchLabels["app"])

	// Security preset: strict
	require.NotNil(t, policy.Spec.Security)
	assert.True(t, *policy.Spec.Security.BlockPrivateIPs)
	assert.True(t, *policy.Spec.Security.BlockOnDivergence)
	assert.Equal(t, int32(3), *policy.Spec.Security.MinResolverAgreement)

	// Check rules:
	// *.stripe.com, api.github.com, login.auth0.com
	ruleMatches := make([]string, 0, len(policy.Spec.Egress))
	for _, r := range policy.Spec.Egress {
		ruleMatches = append(ruleMatches, r.Match)
	}

	assert.Contains(t, ruleMatches, "*.stripe.com")
	assert.Contains(t, ruleMatches, "api.github.com")
	assert.Contains(t, ruleMatches, "login.auth0.com")
	assert.NotContains(t, ruleMatches, "api.stripe.com") // merged into wildcard
	assert.NotContains(t, ruleMatches, "coredns.kube-system.svc.cluster.local")
	assert.NotContains(t, ruleMatches, "kubernetes.default.svc")
}

func TestSimulateCmd_Offline(t *testing.T) {
	tempDir := t.TempDir()
	policyFile := filepath.Join(tempDir, "policy.yaml")
	baselineFile := filepath.Join(tempDir, "baseline.yaml")

	now := metav1.NewTime(time.Now())

	// Policy allowing *.stripe.com and api.github.com
	policy := netv1alpha1.FQDNNetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			APIVersion: netv1alpha1.GroupVersion.String(),
			Kind:       "FQDNNetworkPolicy",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-policy",
			Namespace: "default",
		},
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
	pData, err := yaml.Marshal(policy)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(policyFile, pData, 0644))

	// Baseline observed traffic including an unpolicied domain
	baseline := netv1alpha1.FQDNEgressObservation{
		Status: netv1alpha1.FQDNEgressObservationStatus{
			ObservedDomains: []netv1alpha1.ObservedDomain{
				{Hostname: "api.stripe.com", QueryCount: 10, LastSeen: now},
				{Hostname: "api.github.com", QueryCount: 5, LastSeen: now},
				// Unpolicied external domain (The Blast Radius!)
				{Hostname: "telemetry.datadoghq.com", QueryCount: 100, LastSeen: now},
			},
		},
	}
	bData, err := yaml.Marshal(baseline)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(baselineFile, bData, 0644))

	// 1. Normal simulate (JSON mode)
	simulateBaseline = baselineFile
	simulateFailBlocked = false
	simulateJSON = true
	namespace = "default"

	err = runSimulate(nil, []string{policyFile})
	require.NoError(t, err)

	// 2. Simulate with --fail-on-blocked
	simulateFailBlocked = true
	err = runSimulate(nil, []string{policyFile})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "blast radius check failed: 1 observed domain(s) would be blocked")
}
