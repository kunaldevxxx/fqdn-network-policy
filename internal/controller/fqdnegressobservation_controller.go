package controller

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	netv1alpha1 "github.com/kunaldevxxx/fqdn-network-policy/api/v1alpha1"
	"github.com/kunaldevxxx/fqdn-network-policy/internal/dns"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// FQDNEgressObservationReconciler discovers hostnames queried over DNS
// cluster-wide, via the SnoopResolver, and accumulates them into status so
// operators can write an FQDNNetworkPolicy without guessing. See Issue #8.
//
// Observations are cluster-wide, not scoped to spec.PodSelector or this
// object's namespace -- see FQDNEgressObservationSpec's doc comment for why.
type FQDNEgressObservationReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	// Snoop is nil when the snoop resolver isn't enabled. This controller
	// requires it to be active -- it's the only source of observation data.
	Snoop *dns.SnoopResolver

	syncedMu     sync.Mutex
	syncedCounts map[string]map[string]int64
}

// +kubebuilder:rbac:groups=netsec.kunal.dev,resources=fqdnegressobservations,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=netsec.kunal.dev,resources=fqdnegressobservations/status,verbs=get;update;patch

func (r *FQDNEgressObservationReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var obs netv1alpha1.FQDNEgressObservation
	if err := r.Get(ctx, req.NamespacedName, &obs); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	if r.Snoop == nil {
		setObservationCondition(&obs, "Degraded", metav1.ConditionTrue, "SnoopResolverInactive",
			"snoop resolver is not active; FQDNEgressObservation requires --enable-snoop-resolver")
		setObservationCondition(&obs, "Ready", metav1.ConditionFalse, "SnoopResolverInactive",
			"no observation data available without the snoop resolver")
		obs.Status.ObservedGeneration = obs.Generation
		if err := r.Status().Update(ctx, &obs); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: defaultPollInterval}, nil
	}

	r.syncedMu.Lock()
	if r.syncedCounts == nil {
		r.syncedCounts = make(map[string]map[string]int64)
	}
	key := req.String()
	lastSynced := r.syncedCounts[key]
	if lastSynced == nil {
		lastSynced = make(map[string]int64)
		r.syncedCounts[key] = lastSynced
	}
	r.syncedMu.Unlock()

	live := r.Snoop.Observations().AllDomains()
	obs.Status.ObservedDomains = mergeObservedDomains(obs.Status.ObservedDomains, live, lastSynced)
	obs.Status.ObservationComplete = time.Since(obs.CreationTimestamp.Time) >= obs.Spec.ObservationWindow.Duration
	obs.Status.ObservedGeneration = obs.Generation

	setObservationCondition(&obs, "Ready", metav1.ConditionTrue, "Observing",
		fmt.Sprintf("%d domains observed cluster-wide (podSelector not yet enforced)", len(obs.Status.ObservedDomains)))
	setObservationCondition(&obs, "Degraded", metav1.ConditionFalse, "OK", "")

	if err := r.Status().Update(ctx, &obs); err != nil {
		return ctrl.Result{}, err
	}

	logger.V(1).Info("observation reconciled",
		"name", obs.Name, "domains", len(obs.Status.ObservedDomains))
	return ctrl.Result{RequeueAfter: defaultPollInterval}, nil
}

// mergeObservedDomains additively merges newly observed domains into the
// existing status: a hostname already known keeps its FirstSeen, advances
// LastSeen, and additively tracks QueryCount without double counting.
func mergeObservedDomains(
	existing []netv1alpha1.ObservedDomain,
	live map[string]dns.FirstLastSeen,
	lastSynced map[string]int64,
) []netv1alpha1.ObservedDomain {
	byHostname := make(map[string]netv1alpha1.ObservedDomain, len(existing)+len(live))
	hostnames := make([]string, 0, len(existing)+len(live))

	for _, d := range existing {
		byHostname[d.Hostname] = d
		hostnames = append(hostnames, d.Hostname)
	}

	for hostname, seen := range live {
		prevCount := lastSynced[hostname]
		delta := seen.QueryCount - prevCount
		if delta < 0 {
			delta = seen.QueryCount
		}
		lastSynced[hostname] = seen.QueryCount

		d, ok := byHostname[hostname]
		if !ok {
			byHostname[hostname] = netv1alpha1.ObservedDomain{
				Hostname:   hostname,
				FirstSeen:  metav1.NewTime(seen.FirstSeen),
				LastSeen:   metav1.NewTime(seen.LastSeen),
				QueryCount: delta,
			}
			hostnames = append(hostnames, hostname)
			continue
		}
		if seen.FirstSeen.Before(d.FirstSeen.Time) {
			d.FirstSeen = metav1.NewTime(seen.FirstSeen)
		}
		if seen.LastSeen.After(d.LastSeen.Time) {
			d.LastSeen = metav1.NewTime(seen.LastSeen)
		}
		d.QueryCount += delta
		byHostname[hostname] = d
	}

	sort.Strings(hostnames)
	result := make([]netv1alpha1.ObservedDomain, 0, len(hostnames))
	for _, hostname := range hostnames {
		result = append(result, byHostname[hostname])
	}
	return result
}

func setObservationCondition(
	obs *netv1alpha1.FQDNEgressObservation, condType string, status metav1.ConditionStatus, reason, msg string,
) {
	cond := metav1.Condition{
		Type:               condType,
		Status:             status,
		Reason:             reason,
		Message:            msg,
		ObservedGeneration: obs.Generation,
		LastTransitionTime: metav1.Now(),
	}
	for i, c := range obs.Status.Conditions {
		if c.Type == condType {
			if c.Status == status {
				cond.LastTransitionTime = c.LastTransitionTime
			}
			obs.Status.Conditions[i] = cond
			return
		}
	}
	obs.Status.Conditions = append(obs.Status.Conditions, cond)
}

func (r *FQDNEgressObservationReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&netv1alpha1.FQDNEgressObservation{}).
		Complete(r)
}
