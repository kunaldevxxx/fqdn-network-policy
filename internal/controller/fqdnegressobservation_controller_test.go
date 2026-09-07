package controller

import (
	"context"
	"testing"

	netv1alpha1 "github.com/kunaldevxxx/fqdn-network-policy/api/v1alpha1"
	idns "github.com/kunaldevxxx/fqdn-network-policy/internal/dns"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func conditionStatus(conds []metav1.Condition, condType string) metav1.ConditionStatus {
	for _, c := range conds {
		if c.Type == condType {
			return c.Status
		}
	}
	return ""
}

func TestFQDNEgressObservationReconciler_SnoopInactive_SetsDegraded(t *testing.T) {
	scheme := newTestScheme(t)
	obs := &netv1alpha1.FQDNEgressObservation{
		ObjectMeta: metav1.ObjectMeta{Name: "checkout", Namespace: "payments"},
		Spec: netv1alpha1.FQDNEgressObservationSpec{
			ObservationWindow: metav1.Duration{Duration: 0},
		},
	}
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(obs).
		WithStatusSubresource(obs).
		Build()

	r := &FQDNEgressObservationReconciler{Client: fakeClient, Scheme: scheme, Snoop: nil}
	_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(obs)})
	require.NoError(t, err)

	var updated netv1alpha1.FQDNEgressObservation
	require.NoError(t, fakeClient.Get(context.Background(), client.ObjectKeyFromObject(obs), &updated))
	assert.Equal(t, metav1.ConditionTrue, conditionStatus(updated.Status.Conditions, "Degraded"))
	assert.Equal(t, metav1.ConditionFalse, conditionStatus(updated.Status.Conditions, "Ready"))
}

func TestFQDNEgressObservationReconciler_PopulatesObservedDomainsClusterWide(t *testing.T) {
	scheme := newTestScheme(t)
	obs := &netv1alpha1.FQDNEgressObservation{
		ObjectMeta: metav1.ObjectMeta{Name: "checkout", Namespace: "payments"},
		Spec: netv1alpha1.FQDNEgressObservationSpec{
			PodSelector:       netv1alpha1.PodSelectorSpec{PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "checkout"}}},
			ObservationWindow: metav1.Duration{Duration: 0},
		},
	}
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(obs).
		WithStatusSubresource(obs).
		Build()

	// A real UDP listener isn't needed to exercise the controller: the
	// observation store is populated directly, the way the DNS proxy would.
	// Observations are cluster-wide (see ObservationStore's doc comment for
	// why), so PodSelector plays no filtering role here.
	snoop := idns.NewSnoopResolver("127.0.0.1:0", "127.0.0.1:53")
	snoop.Observations().Record("api.stripe.com")

	r := &FQDNEgressObservationReconciler{Client: fakeClient, Scheme: scheme, Snoop: snoop}
	req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(obs)}
	_, err := r.Reconcile(context.Background(), req)
	require.NoError(t, err)

	var updated netv1alpha1.FQDNEgressObservation
	require.NoError(t, fakeClient.Get(context.Background(), req.NamespacedName, &updated))
	require.Len(t, updated.Status.ObservedDomains, 1)
	assert.Equal(t, "api.stripe.com", updated.Status.ObservedDomains[0].Hostname)
	assert.Equal(t, metav1.ConditionTrue, conditionStatus(updated.Status.Conditions, "Ready"))

	// Second reconcile with a new hostname observed: status should
	// accumulate additively rather than replace, per Issue #8's restart
	// durability requirement.
	snoop.Observations().Record("api.github.com")
	_, err = r.Reconcile(context.Background(), req)
	require.NoError(t, err)

	require.NoError(t, fakeClient.Get(context.Background(), req.NamespacedName, &updated))
	require.Len(t, updated.Status.ObservedDomains, 2)
}
