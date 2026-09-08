package controller

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	netv1alpha1 "github.com/kunaldevxxx/fqdn-network-policy/api/v1alpha1"
	"github.com/kunaldevxxx/fqdn-network-policy/internal/dns"
	"github.com/kunaldevxxx/fqdn-network-policy/internal/enrich"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// stubResolver returns a fixed Resolution for every hostname.
type stubResolver struct {
	res dns.Resolution
	err error
}

func (s *stubResolver) Resolve(_ context.Context, hostname string) (dns.Resolution, error) {
	r := s.res
	r.Hostname = hostname
	return r, s.err
}

func waitForTest(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	require.Fail(t, "condition not met within timeout")
}

func newTestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))
	require.NoError(t, networkingv1.AddToScheme(scheme))
	require.NoError(t, netv1alpha1.AddToScheme(scheme))
	return scheme
}

// TestFQDNNetworkPolicyReconciler_PopulatesIPEnrichments is the "mock
// enricher backend, verify status field is populated correctly" acceptance
// test for Issue #9.
func TestFQDNNetworkPolicyReconciler_PopulatesIPEnrichments(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"org":     "AS15169 Google LLC",
			"country": "US",
		})
	}))
	defer server.Close()

	scheme := newTestScheme(t)
	fp := &netv1alpha1.FQDNNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Namespace: "default"},
		Spec: netv1alpha1.FQDNNetworkPolicySpec{
			Egress: []netv1alpha1.FQDNRule{{Match: "api.example.com"}},
		},
	}
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(fp).
		WithStatusSubresource(fp).
		Build()

	enricher := enrich.NewManager(&enrich.IPInfoClient{BaseURL: server.URL}, logr.Discard())
	defer enricher.Close()

	r := &FQDNNetworkPolicyReconciler{
		Client:   fakeClient,
		Scheme:   scheme,
		Resolver: &stubResolver{res: dns.Resolution{IPs: []string{"8.8.8.8"}, TTL: 60 * time.Second}},
		Recorder: record.NewFakeRecorder(10),
		Enricher: enricher,
	}
	req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(fp)}
	ctx := context.Background()

	// First reconcile only triggers the async enrichment request.
	_, err := r.Reconcile(ctx, req)
	require.NoError(t, err)

	waitForTest(t, time.Second, func() bool {
		_, _, ok := enricher.Get("8.8.8.8")
		return ok
	})

	// Second reconcile should now find the enrichment cached and populate status.
	_, err = r.Reconcile(ctx, req)
	require.NoError(t, err)

	var updated netv1alpha1.FQDNNetworkPolicy
	require.NoError(t, fakeClient.Get(ctx, req.NamespacedName, &updated))
	require.Len(t, updated.Status.ResolvedHosts, 1)

	enrichment, ok := updated.Status.ResolvedHosts[0].IPEnrichments["8.8.8.8"]
	require.True(t, ok, "IPEnrichments should be populated once the enricher's cache is warm")
	assert.Equal(t, "AS15169", enrichment.ASN)
	assert.Equal(t, "Google LLC", enrichment.Org)
	assert.Equal(t, "US", enrichment.Country)
}

// TestFQDNNetworkPolicyReconciler_ResolverDivergence_SetsCondition is the
// "two resolvers disagree, status field and condition are populated"
// acceptance test for Issue #4.
func TestFQDNNetworkPolicyReconciler_ResolverDivergence_SetsCondition(t *testing.T) {
	scheme := newTestScheme(t)
	fp := &netv1alpha1.FQDNNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Namespace: "default"},
		Spec: netv1alpha1.FQDNNetworkPolicySpec{
			Egress: []netv1alpha1.FQDNRule{{Match: "api.stripe.com"}},
		},
	}
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(fp).
		WithStatusSubresource(fp).
		Build()

	r := &FQDNNetworkPolicyReconciler{
		Client: fakeClient,
		Scheme: scheme,
		Resolver: &stubResolver{res: dns.Resolution{
			IPs:                []string{"1.1.1.1", "2.2.2.2"},
			TTL:                60 * time.Second,
			ResolverDivergence: 2,
			ResolverResults: map[string][]string{
				"1.1.1.1:53": {"1.1.1.1"},
				"8.8.8.8:53": {"2.2.2.2"},
			},
		}},
		Recorder: record.NewFakeRecorder(10),
	}
	req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(fp)}
	ctx := context.Background()

	_, err := r.Reconcile(ctx, req)
	require.NoError(t, err)

	var updated netv1alpha1.FQDNNetworkPolicy
	require.NoError(t, fakeClient.Get(ctx, req.NamespacedName, &updated))
	require.Len(t, updated.Status.ResolvedHosts, 1)

	sec := updated.Status.ResolvedHosts[0].Security
	require.NotNil(t, sec)
	assert.Equal(t, 2, sec.ResolverDivergence)
	assert.Len(t, sec.ResolverResults, 2)

	assert.Equal(t, metav1.ConditionTrue, conditionStatus(updated.Status.Conditions, "ResolverDivergence"))
}

func TestFQDNNetworkPolicyReconciler_NoDivergence_ConditionFalse_ResultsEmpty(t *testing.T) {
	scheme := newTestScheme(t)
	fp := &netv1alpha1.FQDNNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Namespace: "default"},
		Spec: netv1alpha1.FQDNNetworkPolicySpec{
			Egress: []netv1alpha1.FQDNRule{{Match: "api.example.com"}},
		},
	}
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(fp).
		WithStatusSubresource(fp).
		Build()

	r := &FQDNNetworkPolicyReconciler{
		Client:   fakeClient,
		Scheme:   scheme,
		Resolver: &stubResolver{res: dns.Resolution{IPs: []string{"8.8.8.8"}, TTL: 60 * time.Second}},
		Recorder: record.NewFakeRecorder(10),
	}
	req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(fp)}
	ctx := context.Background()

	_, err := r.Reconcile(ctx, req)
	require.NoError(t, err)

	var updated netv1alpha1.FQDNNetworkPolicy
	require.NoError(t, fakeClient.Get(ctx, req.NamespacedName, &updated))
	require.Len(t, updated.Status.ResolvedHosts, 1)
	assert.Empty(t, updated.Status.ResolvedHosts[0].Security.ResolverResults)
	assert.Equal(t, metav1.ConditionFalse, conditionStatus(updated.Status.Conditions, "ResolverDivergence"))
}

// TestFQDNNetworkPolicyReconciler_ConsensusMode_DropsMinorityIP is the
// "consensus mode filters IPs below the agreement threshold" test for
// Issue #4's opt-in follow-on.
func TestFQDNNetworkPolicyReconciler_ConsensusMode_DropsMinorityIP(t *testing.T) {
	scheme := newTestScheme(t)
	minAgreement := int32(2)
	fp := &netv1alpha1.FQDNNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Namespace: "default"},
		Spec: netv1alpha1.FQDNNetworkPolicySpec{
			Egress:   []netv1alpha1.FQDNRule{{Match: "api.stripe.com"}},
			Security: &netv1alpha1.SecuritySpec{MinResolverAgreement: &minAgreement},
		},
	}
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(fp).
		WithStatusSubresource(fp).
		Build()

	r := &FQDNNetworkPolicyReconciler{
		Client: fakeClient,
		Scheme: scheme,
		Resolver: &stubResolver{res: dns.Resolution{
			IPs: []string{"1.1.1.1", "2.2.2.2"},
			TTL: 60 * time.Second,
			ResolverResults: map[string][]string{
				"a": {"1.1.1.1"},
				"b": {"1.1.1.1", "2.2.2.2"},
				"c": {"1.1.1.1"},
			},
		}},
		Recorder: record.NewFakeRecorder(10),
	}
	req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(fp)}
	ctx := context.Background()

	_, err := r.Reconcile(ctx, req)
	require.NoError(t, err)

	var updated netv1alpha1.FQDNNetworkPolicy
	require.NoError(t, fakeClient.Get(ctx, req.NamespacedName, &updated))
	require.Len(t, updated.Status.ResolvedHosts, 1)
	assert.Equal(t, []string{"1.1.1.1"}, updated.Status.ResolvedHosts[0].IPs)
}

// TestFQDNNetworkPolicyReconciler_BlockOnDivergence_SkipsApply is the
// "opt-in divergence blocking freezes the NetworkPolicy" test for Issue #4's
// other opt-in follow-on.
func TestFQDNNetworkPolicyReconciler_BlockOnDivergence_SkipsApply(t *testing.T) {
	scheme := newTestScheme(t)
	blockOn := true
	fp := &netv1alpha1.FQDNNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Namespace: "default"},
		Spec: netv1alpha1.FQDNNetworkPolicySpec{
			Egress:   []netv1alpha1.FQDNRule{{Match: "api.stripe.com"}},
			Security: &netv1alpha1.SecuritySpec{BlockOnDivergence: &blockOn},
		},
	}
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(fp).
		WithStatusSubresource(fp).
		Build()

	r := &FQDNNetworkPolicyReconciler{
		Client: fakeClient,
		Scheme: scheme,
		Resolver: &stubResolver{res: dns.Resolution{
			IPs:                []string{"1.1.1.1", "2.2.2.2"},
			TTL:                60 * time.Second,
			ResolverDivergence: 2,
			ResolverResults:    map[string][]string{"a": {"1.1.1.1"}, "b": {"2.2.2.2"}},
		}},
		Recorder: record.NewFakeRecorder(10),
	}
	req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(fp)}
	ctx := context.Background()

	_, err := r.Reconcile(ctx, req)
	require.NoError(t, err)

	var updated netv1alpha1.FQDNNetworkPolicy
	require.NoError(t, fakeClient.Get(ctx, req.NamespacedName, &updated))
	assert.Empty(t, updated.Status.GeneratedNetworkPolicy, "no NetworkPolicy should have been generated/applied")
	assert.Equal(t, metav1.ConditionFalse, conditionStatus(updated.Status.Conditions, "Ready"))
	assert.Equal(t, metav1.ConditionTrue, conditionStatus(updated.Status.Conditions, "Degraded"))

	var npList networkingv1.NetworkPolicyList
	require.NoError(t, fakeClient.List(ctx, &npList))
	assert.Empty(t, npList.Items, "no NetworkPolicy object should have been created")
}

// TestFQDNNetworkPolicyReconciler_DetectsUnpoliciedDrift is the "snoop
// resolver observes a hostname not in any policy, status field is
// populated" acceptance test for Issue #6.
func TestFQDNNetworkPolicyReconciler_DetectsUnpoliciedDrift(t *testing.T) {
	scheme := newTestScheme(t)
	fp := &netv1alpha1.FQDNNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "checkout", Namespace: "payments"},
		Spec: netv1alpha1.FQDNNetworkPolicySpec{
			Egress: []netv1alpha1.FQDNRule{{Match: "api.stripe.com"}},
		},
	}
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(fp).
		WithStatusSubresource(fp).
		Build()

	// A real UDP listener isn't needed: the observation store is populated
	// directly, the way the DNS proxy would (same pattern as
	// fqdnegressobservation_controller_test.go).
	snoop := dns.NewSnoopResolver("127.0.0.1:0", "127.0.0.1:53")
	snoop.Observations().Record("api.stripe.com")       // covered by fp's own egress rule
	snoop.Observations().Record("telemetry.vendor.com") // not covered by any policy in this namespace

	r := &FQDNNetworkPolicyReconciler{
		Client:   fakeClient,
		Scheme:   scheme,
		Resolver: &stubResolver{res: dns.Resolution{IPs: []string{"1.2.3.4"}, TTL: 60 * time.Second}},
		Recorder: record.NewFakeRecorder(10),
		Snoop:    snoop,
	}
	req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(fp)}
	ctx := context.Background()

	_, err := r.Reconcile(ctx, req)
	require.NoError(t, err)

	var updated netv1alpha1.FQDNNetworkPolicy
	require.NoError(t, fakeClient.Get(ctx, req.NamespacedName, &updated))
	require.Len(t, updated.Status.ObservedUnpoliciedDomains, 1)
	assert.Equal(t, "telemetry.vendor.com", updated.Status.ObservedUnpoliciedDomains[0].Hostname)
}

func TestFQDNNetworkPolicyReconciler_NoSnoop_NoUnpoliciedDomains(t *testing.T) {
	scheme := newTestScheme(t)
	fp := &netv1alpha1.FQDNNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "checkout", Namespace: "payments"},
		Spec: netv1alpha1.FQDNNetworkPolicySpec{
			Egress: []netv1alpha1.FQDNRule{{Match: "api.stripe.com"}},
		},
	}
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(fp).
		WithStatusSubresource(fp).
		Build()

	r := &FQDNNetworkPolicyReconciler{
		Client:   fakeClient,
		Scheme:   scheme,
		Resolver: &stubResolver{res: dns.Resolution{IPs: []string{"1.2.3.4"}, TTL: 60 * time.Second}},
		Recorder: record.NewFakeRecorder(10),
		// Snoop intentionally nil: no behavior change without it.
	}
	req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(fp)}
	ctx := context.Background()

	_, err := r.Reconcile(ctx, req)
	require.NoError(t, err)

	var updated netv1alpha1.FQDNNetworkPolicy
	require.NoError(t, fakeClient.Get(ctx, req.NamespacedName, &updated))
	assert.Empty(t, updated.Status.ObservedUnpoliciedDomains)
}

// TestFQDNNetworkPolicyReconciler_DriftClearsWhenPolicyCovers proves the
// "drift data is cleared when a matching policy is created" acceptance
// criterion, since the field is recomputed fresh every reconcile.
func TestFQDNNetworkPolicyReconciler_DriftClearsWhenPolicyCovers(t *testing.T) {
	scheme := newTestScheme(t)
	fp := &netv1alpha1.FQDNNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "checkout", Namespace: "payments"},
		Spec: netv1alpha1.FQDNNetworkPolicySpec{
			Egress: []netv1alpha1.FQDNRule{{Match: "api.stripe.com"}},
		},
	}
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(fp).
		WithStatusSubresource(fp).
		Build()

	snoop := dns.NewSnoopResolver("127.0.0.1:0", "127.0.0.1:53")
	snoop.Observations().Record("api.stripe.com")
	snoop.Observations().Record("telemetry.vendor.com")

	r := &FQDNNetworkPolicyReconciler{
		Client:   fakeClient,
		Scheme:   scheme,
		Resolver: &stubResolver{res: dns.Resolution{IPs: []string{"1.2.3.4"}, TTL: 60 * time.Second}},
		Recorder: record.NewFakeRecorder(10),
		Snoop:    snoop,
	}
	req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(fp)}
	ctx := context.Background()

	_, err := r.Reconcile(ctx, req)
	require.NoError(t, err)

	var updated netv1alpha1.FQDNNetworkPolicy
	require.NoError(t, fakeClient.Get(ctx, req.NamespacedName, &updated))
	require.Len(t, updated.Status.ObservedUnpoliciedDomains, 1, "telemetry.vendor.com should show as drift before a covering policy exists")

	// A second policy in the same namespace now covers the drifted domain.
	covering := &netv1alpha1.FQDNNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "telemetry", Namespace: "payments"},
		Spec: netv1alpha1.FQDNNetworkPolicySpec{
			Egress: []netv1alpha1.FQDNRule{{Match: "telemetry.vendor.com"}},
		},
	}
	require.NoError(t, fakeClient.Create(ctx, covering))

	_, err = r.Reconcile(ctx, req)
	require.NoError(t, err)

	require.NoError(t, fakeClient.Get(ctx, req.NamespacedName, &updated))
	assert.Empty(t, updated.Status.ObservedUnpoliciedDomains, "drift should clear once a policy in the namespace covers the domain")
}

func TestFQDNNetworkPolicyReconciler_NoEnricher_NoIPEnrichments(t *testing.T) {
	scheme := newTestScheme(t)
	fp := &netv1alpha1.FQDNNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Namespace: "default"},
		Spec: netv1alpha1.FQDNNetworkPolicySpec{
			Egress: []netv1alpha1.FQDNRule{{Match: "api.example.com"}},
		},
	}
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(fp).
		WithStatusSubresource(fp).
		Build()

	r := &FQDNNetworkPolicyReconciler{
		Client:   fakeClient,
		Scheme:   scheme,
		Resolver: &stubResolver{res: dns.Resolution{IPs: []string{"8.8.8.8"}, TTL: 60 * time.Second}},
		Recorder: record.NewFakeRecorder(10),
		// Enricher intentionally nil: the ASN enricher is opt-in and disabled by default.
	}
	req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(fp)}
	ctx := context.Background()

	_, err := r.Reconcile(ctx, req)
	require.NoError(t, err)

	var updated netv1alpha1.FQDNNetworkPolicy
	require.NoError(t, fakeClient.Get(ctx, req.NamespacedName, &updated))
	require.Len(t, updated.Status.ResolvedHosts, 1)
	assert.Empty(t, updated.Status.ResolvedHosts[0].IPEnrichments)
}
