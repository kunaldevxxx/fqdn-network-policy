package controller

import (
	"context"
	"testing"
	"time"

	netv1alpha1 "github.com/kunaldevxxx/fqdn-network-policy/api/v1alpha1"
	"github.com/kunaldevxxx/fqdn-network-policy/internal/dns"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestClusterFQDNNetworkPolicyReconciler_FansOutToMatchedNamespace(t *testing.T) {
	scheme := newTestScheme(t)
	cp := &netv1alpha1.ClusterFQDNNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "baseline"},
		Spec: netv1alpha1.ClusterFQDNNetworkPolicySpec{
			Egress: []netv1alpha1.FQDNRule{{Match: "api.stripe.com"}},
		},
	}
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: "payments"},
		Status:     corev1.NamespaceStatus{Phase: corev1.NamespaceActive},
	}
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cp, ns).
		WithStatusSubresource(cp).
		Build()

	r := &ClusterFQDNNetworkPolicyReconciler{
		Client:   fakeClient,
		Scheme:   scheme,
		Resolver: &stubResolver{res: dns.Resolution{IPs: []string{"1.2.3.4"}, TTL: 60 * time.Second}},
		Recorder: record.NewFakeRecorder(10),
	}
	req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(cp)}
	ctx := context.Background()

	_, err := r.Reconcile(ctx, req)
	require.NoError(t, err)

	var updated netv1alpha1.ClusterFQDNNetworkPolicy
	require.NoError(t, fakeClient.Get(ctx, req.NamespacedName, &updated))
	assert.Equal(t, []string{"payments"}, updated.Status.AffectedNamespaces)
	assert.Equal(t, metav1.ConditionTrue, conditionStatus(updated.Status.Conditions, "Ready"))

	var np networkingv1.NetworkPolicy
	require.NoError(t, fakeClient.Get(ctx, client.ObjectKey{Namespace: "payments", Name: "fqdnnp-cfqdnnp-baseline"}, &np))
}

// TestClusterFQDNNetworkPolicyReconciler_BlockOnDivergence_SkipsFanOut is the
// cluster-scoped counterpart of the namespaced BlockOnDivergence test.
func TestClusterFQDNNetworkPolicyReconciler_BlockOnDivergence_SkipsFanOut(t *testing.T) {
	scheme := newTestScheme(t)
	blockOn := true
	cp := &netv1alpha1.ClusterFQDNNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "baseline"},
		Spec: netv1alpha1.ClusterFQDNNetworkPolicySpec{
			Egress:   []netv1alpha1.FQDNRule{{Match: "api.stripe.com"}},
			Security: &netv1alpha1.SecuritySpec{BlockOnDivergence: &blockOn},
		},
	}
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: "payments"},
		Status:     corev1.NamespaceStatus{Phase: corev1.NamespaceActive},
	}
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cp, ns).
		WithStatusSubresource(cp).
		Build()

	r := &ClusterFQDNNetworkPolicyReconciler{
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
	req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(cp)}
	ctx := context.Background()

	_, err := r.Reconcile(ctx, req)
	require.NoError(t, err)

	var updated netv1alpha1.ClusterFQDNNetworkPolicy
	require.NoError(t, fakeClient.Get(ctx, req.NamespacedName, &updated))
	assert.Equal(t, metav1.ConditionFalse, conditionStatus(updated.Status.Conditions, "Ready"))
	assert.Equal(t, metav1.ConditionTrue, conditionStatus(updated.Status.Conditions, "ResolverDivergence"))

	var npList networkingv1.NetworkPolicyList
	require.NoError(t, fakeClient.List(ctx, &npList))
	assert.Empty(t, npList.Items, "no NetworkPolicy should have been created while blocked")
}
