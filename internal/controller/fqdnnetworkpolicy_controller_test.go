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
