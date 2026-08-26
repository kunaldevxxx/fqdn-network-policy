package controller

import (
	"context"
	"strings"
	"time"

	netv1alpha1 "github.com/kunaldevxxx/fqdn-network-policy/api/v1alpha1"
	"github.com/kunaldevxxx/fqdn-network-policy/internal/dns"
	"github.com/kunaldevxxx/fqdn-network-policy/internal/netpol"

	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// defaultPollInterval is used when a resolution carries no usable TTL.
const defaultPollInterval = 60 * time.Second

// FQDNNetworkPolicyReconciler reconciles a FQDNNetworkPolicy object.
type FQDNNetworkPolicyReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Resolver dns.Resolver // swap for dns.NewSnoopResolver() once implemented
}

// +kubebuilder:rbac:groups=netsec.kunal.dev,resources=fqdnnetworkpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=netsec.kunal.dev,resources=fqdnnetworkpolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=networking.k8s.io,resources=networkpolicies,verbs=get;list;watch;create;update;patch;delete

func (r *FQDNNetworkPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var fp netv1alpha1.FQDNNetworkPolicy
	if err := r.Get(ctx, req.NamespacedName, &fp); err != nil {
		if apierrors.IsNotFound(err) {
			// Owned NetworkPolicy is garbage-collected via OwnerReference.
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	// 1. Resolve every hostname rule. Wildcard patterns are flagged rather
	// than silently dropped, since ActiveResolver can't expand them; this
	// is exactly the seam SnoopResolver fills in later without touching
	// this loop.
	resolved := make([]netv1alpha1.ResolvedHost, 0, len(fp.Spec.Egress))
	nextRequeue := defaultPollInterval
	var resolutionErrors []string

	for _, rule := range fp.Spec.Egress {
		if strings.Contains(rule.Match, "*") {
			resolutionErrors = append(resolutionErrors,
				"wildcard pattern \""+rule.Match+"\" requires the snoop resolver, skipping")
			continue
		}

		res, err := r.Resolver.Resolve(ctx, rule.Match)
		if err != nil {
			logger.Error(err, "resolution failed", "hostname", rule.Match)
			resolutionErrors = append(resolutionErrors, rule.Match+": "+err.Error())
			// Keep the previous resolution for this host if we have one,
			// rather than dropping egress access on a transient DNS blip.
			if prev := findPrevious(fp.Status.ResolvedHosts, rule.Match); prev != nil {
				resolved = append(resolved, *prev)
			}
			continue
		}

		resolved = append(resolved, netv1alpha1.ResolvedHost{
			Hostname: rule.Match,
			IPs:      res.IPs,
			LastSeen: metav1.Now(),
			Source:   "active-lookup",
		})
	}

	// 2. Build and apply the plain NetworkPolicy this resource owns.
	fp.Status.ResolvedHosts = resolved
	desired, err := netpol.Build(&fp)
	if err != nil {
		return ctrl.Result{}, err
	}

	if err := r.applyNetworkPolicy(ctx, desired); err != nil {
		return ctrl.Result{}, err
	}

	// 3. Update status.
	fp.Status.GeneratedNetworkPolicy = desired.Name
	fp.Status.ObservedGeneration = fp.Generation
	setReadyCondition(&fp, resolutionErrors)

	if err := r.Status().Update(ctx, &fp); err != nil {
		return ctrl.Result{}, err
	}

	if fp.Spec.ResolutionTTLOverride != nil {
		nextRequeue = time.Duration(*fp.Spec.ResolutionTTLOverride) * time.Second
	}
	return ctrl.Result{RequeueAfter: nextRequeue}, nil
}

func (r *FQDNNetworkPolicyReconciler) applyNetworkPolicy(ctx context.Context, desired *networkingv1.NetworkPolicy) error {
	var existing networkingv1.NetworkPolicy
	err := r.Get(ctx, client.ObjectKeyFromObject(desired), &existing)
	switch {
	case apierrors.IsNotFound(err):
		return r.Create(ctx, desired)
	case err != nil:
		return err
	default:
		existing.Spec = desired.Spec
		existing.Labels = desired.Labels
		return r.Update(ctx, &existing)
	}
}

func findPrevious(hosts []netv1alpha1.ResolvedHost, hostname string) *netv1alpha1.ResolvedHost {
	for i := range hosts {
		if hosts[i].Hostname == hostname {
			return &hosts[i]
		}
	}
	return nil
}

func setReadyCondition(fp *netv1alpha1.FQDNNetworkPolicy, resolutionErrors []string) {
	cond := metav1.Condition{
		Type:               "Ready",
		Status:             metav1.ConditionTrue,
		Reason:             "Reconciled",
		Message:            "NetworkPolicy generated from resolved hosts",
		ObservedGeneration: fp.Generation,
		LastTransitionTime: metav1.Now(),
	}
	if len(resolutionErrors) > 0 {
		cond.Status = metav1.ConditionFalse
		cond.Reason = "ResolutionDegraded"
		cond.Message = strings.Join(resolutionErrors, "; ")
	}
	meta_SetStatusCondition(&fp.Status.Conditions, cond)
}

// meta_SetStatusCondition mirrors k8s.io/apimachinery/pkg/api/meta.SetStatusCondition
// (kept local + trivial here to avoid pulling in an extra import in the sketch;
// swap for the real helper when wiring this up for real).
func meta_SetStatusCondition(conditions *[]metav1.Condition, newCond metav1.Condition) {
	for i, c := range *conditions {
		if c.Type == newCond.Type {
			(*conditions)[i] = newCond
			return
		}
	}
	*conditions = append(*conditions, newCond)
}

func (r *FQDNNetworkPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&netv1alpha1.FQDNNetworkPolicy{}).
		Owns(&networkingv1.NetworkPolicy{}).
		Complete(r)
}

var _ = controllerutil.SetControllerReference // keep import if wiring owner refs manually elsewhere
