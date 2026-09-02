package controller

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	netv1alpha1 "github.com/kunaldevxxx/fqdn-network-policy/api/v1alpha1"
	"github.com/kunaldevxxx/fqdn-network-policy/internal/dns"
	"github.com/kunaldevxxx/fqdn-network-policy/internal/metrics"
	"github.com/kunaldevxxx/fqdn-network-policy/internal/netpol"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// ClusterFQDNNetworkPolicyReconciler reconciles ClusterFQDNNetworkPolicy objects.
// It resolves FQDNs once and fans out a NetworkPolicy into every namespace
// that matches the policy's NamespaceSelector, keeping them in sync.
type ClusterFQDNNetworkPolicyReconciler struct {
	client.Client
	Scheme       *runtime.Scheme
	Resolver     dns.Resolver
	Recorder     record.EventRecorder
	ChurnTracker *dns.ChurnTracker
}

// +kubebuilder:rbac:groups=netsec.kunal.dev,resources=clusterfqdnnetworkpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=netsec.kunal.dev,resources=clusterfqdnnetworkpolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=networking.k8s.io,resources=networkpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=namespaces,verbs=get;list;watch

func (r *ClusterFQDNNetworkPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var cp netv1alpha1.ClusterFQDNNetworkPolicy
	if err := r.Get(ctx, req.NamespacedName, &cp); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	// Resolve all FQDNs once — the same IP set goes into every matched namespace.
	ttlQueue := dns.NewTTLQueue()
	resolved := make([]netv1alpha1.ResolvedHost, 0, len(cp.Spec.Egress))
	var resolutionErrors []string

	for _, rule := range cp.Spec.Egress {
		timer := time.Now()
		res, err := r.Resolver.Resolve(ctx, rule.Match)
		elapsed := time.Since(timer)
		metrics.DNSLookupDuration.WithLabelValues(rule.Match, "active").Observe(elapsed.Seconds())

		if err != nil {
			logger.Error(err, "resolution failed", "hostname", rule.Match)
			metrics.DNSLookupFailures.WithLabelValues(rule.Match, classifyError(err)).Inc()
			resolutionErrors = append(resolutionErrors, rule.Match+": "+err.Error())
			r.Recorder.Eventf(&cp, "Warning", "ResolutionFailed",
				"DNS lookup failed for %s: %v", rule.Match, err)
			if prev := findPreviousCluster(cp.Status.ResolvedHosts, rule.Match); prev != nil {
				resolved = append(resolved, *prev)
			}
			continue
		}

		ttl := res.TTL
		if ttl == 0 {
			ttl = defaultPollInterval
		}
		ttlQueue.Upsert(rule.Match, ttl)
		// Drop private / loopback / link-local IPs per security policy.
		allowedIPs, blockedIPs := filterBlockedIPs(res.IPs, cp.Spec.Security)
		for _, b := range blockedIPs {
			msg := b.message(rule.Match)
			resolutionErrors = append(resolutionErrors, msg)
			logger.Info("blocked private IP", "hostname", rule.Match, "ip", b.IP, "cidr", b.CIDR)
			r.Recorder.Eventf(&cp, "Warning", "PrivateIPBlocked", "%s", msg)
		}
		if len(allowedIPs) == 0 && len(blockedIPs) > 0 {
			metrics.ResolvedIPsCount.WithLabelValues(rule.Match).Set(0)
			continue
		}

		metrics.ResolvedIPsCount.WithLabelValues(rule.Match).Set(float64(len(allowedIPs)))
		churnRate := 0
		if r.ChurnTracker != nil {
			churnRate = r.ChurnTracker.Record(rule.Match, allowedIPs)
		}
		sec := &netv1alpha1.DNSSecurityMetadata{
			DNSSECValidated:    res.DNSSECValidated,
			IPChurnRate:        churnRate,
			ResolverDivergence: res.ResolverDivergence,
			ShortTTL:           res.TTL > 0 && res.TTL < shortTTLThreshold,
		}
		resolved = append(resolved, netv1alpha1.ResolvedHost{
			Hostname:   rule.Match,
			IPs:        allowedIPs,
			CNAMEChain: res.CNAMEChain,
			LastSeen:   metav1.Now(),
			Source:     "active-lookup",
			TTLSeconds: int32(ttl.Seconds()),
			Security:   sec,
		})

		if cp.Spec.Security != nil && cp.Spec.Security.MaxCNAMEDepth != nil {
			if maxDepth := int(*cp.Spec.Security.MaxCNAMEDepth); maxDepth > 0 && len(res.CNAMEChain) > maxDepth {
				resolutionErrors = append(resolutionErrors,
					fmt.Sprintf("%s: CNAME chain depth %d exceeds maxCNAMEDepth %d",
						rule.Match, len(res.CNAMEChain), maxDepth))
			}
		}
	}

	// List namespaces whose labels match the NamespaceSelector.
	matchedNS, err := r.matchedNamespaces(ctx, &cp)
	if err != nil {
		return ctrl.Result{}, err
	}

	// Audit mode: log and update status, but do not write any NetworkPolicies.
	if cp.Spec.Mode == netv1alpha1.PolicyModeAudit {
		logger.Info("audit mode: no NetworkPolicies written",
			"policy", cp.Name, "namespaces", len(matchedNS))
		r.Recorder.Eventf(&cp, "Normal", "AuditResolved",
			"Audit mode: %d namespaces matched, no NetworkPolicies written", len(matchedNS))
		return r.updateClusterStatus(ctx, &cp, resolved, matchedNS, resolutionErrors, ttlQueue)
	}

	// Enforce mode: fan out one NetworkPolicy per matched namespace.
	for _, ns := range matchedNS {
		synth := r.syntheticPolicy(&cp, ns, resolved)
		desired, err := netpol.Build(synth)
		if err != nil {
			logger.Error(err, "build NetworkPolicy failed", "namespace", ns)
			continue
		}
		// Tag the policy so we can garbage-collect it later.
		desired.Labels["netsec.kunal.dev/cluster-policy"] = cp.Name

		var existing networkingv1.NetworkPolicy
		getErr := r.Get(ctx, client.ObjectKeyFromObject(desired), &existing)
		switch {
		case apierrors.IsNotFound(getErr):
			if createErr := r.Create(ctx, desired); createErr != nil {
				logger.Error(createErr, "create NetworkPolicy failed", "namespace", ns)
				r.Recorder.Eventf(&cp, "Warning", "SyncFailed",
					"Failed to create NetworkPolicy in %s: %v", ns, createErr)
			} else {
				r.Recorder.Eventf(&cp, "Normal", "NetworkPolicyCreated",
					"Created NetworkPolicy %s/%s", ns, desired.Name)
			}
		case getErr != nil:
			logger.Error(getErr, "get NetworkPolicy failed", "namespace", ns)
		default:
			if !ipSetsEqual(existing.Spec.Egress, desired.Spec.Egress) {
				existing.Spec = desired.Spec
				existing.Labels = desired.Labels
				if updateErr := r.Update(ctx, &existing); updateErr != nil {
					logger.Error(updateErr, "update NetworkPolicy failed", "namespace", ns)
				} else {
					r.Recorder.Eventf(&cp, "Normal", "NetworkPolicyUpdated",
						"Updated NetworkPolicy %s/%s", ns, existing.Name)
				}
			}
		}
	}

	// Garbage-collect NetworkPolicies in namespaces that no longer match.
	if gcErr := r.garbageCollect(ctx, &cp, matchedNS); gcErr != nil {
		logger.Error(gcErr, "garbage collection failed")
	}

	return r.updateClusterStatus(ctx, &cp, resolved, matchedNS, resolutionErrors, ttlQueue)
}

// matchedNamespaces lists active namespaces whose labels satisfy NamespaceSelector.
func (r *ClusterFQDNNetworkPolicyReconciler) matchedNamespaces(
	ctx context.Context, cp *netv1alpha1.ClusterFQDNNetworkPolicy,
) ([]string, error) {
	selector, err := metav1.LabelSelectorAsSelector(&cp.Spec.NamespaceSelector)
	if err != nil {
		return nil, err
	}
	var nsList corev1.NamespaceList
	listOpts := &client.ListOptions{}
	if !selector.Empty() {
		listOpts.LabelSelector = selector
	}
	if err := r.List(ctx, &nsList, listOpts); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(nsList.Items))
	for _, ns := range nsList.Items {
		if ns.Status.Phase == corev1.NamespaceActive {
			names = append(names, ns.Name)
		}
	}
	sort.Strings(names)
	return names, nil
}

// syntheticPolicy builds a namespace-scoped FQDNNetworkPolicy from the cluster
// policy so we can reuse netpol.Build for per-namespace NetworkPolicy generation.
func (r *ClusterFQDNNetworkPolicyReconciler) syntheticPolicy(
	cp *netv1alpha1.ClusterFQDNNetworkPolicy,
	namespace string,
	resolved []netv1alpha1.ResolvedHost,
) *netv1alpha1.FQDNNetworkPolicy {
	return &netv1alpha1.FQDNNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "cfqdnnp-" + cp.Name,
			Namespace: namespace,
		},
		Spec: netv1alpha1.FQDNNetworkPolicySpec{
			PodSelector: cp.Spec.PodSelector,
			Egress:      cp.Spec.Egress,
			Mode:        cp.Spec.Mode,
		},
		Status: netv1alpha1.FQDNNetworkPolicyStatus{
			ResolvedHosts: resolved,
		},
	}
}

// garbageCollect deletes NetworkPolicies in namespaces no longer matched.
func (r *ClusterFQDNNetworkPolicyReconciler) garbageCollect(
	ctx context.Context, cp *netv1alpha1.ClusterFQDNNetworkPolicy, active []string,
) error {
	activeSet := make(map[string]struct{}, len(active))
	for _, ns := range active {
		activeSet[ns] = struct{}{}
	}
	var npList networkingv1.NetworkPolicyList
	if err := r.List(ctx, &npList, client.MatchingLabels{
		"netsec.kunal.dev/cluster-policy": cp.Name,
	}); err != nil {
		return err
	}
	for i := range npList.Items {
		np := &npList.Items[i]
		if _, ok := activeSet[np.Namespace]; !ok {
			if err := r.Delete(ctx, np); err != nil && !apierrors.IsNotFound(err) {
				return err
			}
			r.Recorder.Eventf(cp, "Normal", "NetworkPolicyDeleted",
				"Removed NetworkPolicy %s/%s (namespace no longer matches)", np.Namespace, np.Name)
		}
	}
	return nil
}

func (r *ClusterFQDNNetworkPolicyReconciler) updateClusterStatus(
	ctx context.Context,
	cp *netv1alpha1.ClusterFQDNNetworkPolicy,
	resolved []netv1alpha1.ResolvedHost,
	namespaces []string,
	resolutionErrors []string,
	ttlQueue *dns.TTLQueue,
) (ctrl.Result, error) {
	cp.Status.ResolvedHosts = resolved
	cp.Status.AffectedNamespaces = namespaces
	cp.Status.ObservedGeneration = cp.Generation

	cond := metav1.Condition{
		Type:               "Ready",
		ObservedGeneration: cp.Generation,
		LastTransitionTime: metav1.Now(),
	}
	if len(resolutionErrors) > 0 {
		cond.Status = metav1.ConditionFalse
		cond.Reason = "ResolutionDegraded"
		cond.Message = strings.Join(resolutionErrors, "; ")
	} else {
		cond.Status = metav1.ConditionTrue
		cond.Reason = "Reconciled"
		cond.Message = "NetworkPolicies synced to all matched namespaces"
	}
	for i, c := range cp.Status.Conditions {
		if c.Type == cond.Type {
			if c.Status == cond.Status {
				cond.LastTransitionTime = c.LastTransitionTime
			}
			cp.Status.Conditions[i] = cond
			goto updated
		}
	}
	cp.Status.Conditions = append(cp.Status.Conditions, cond)
updated:
	if err := r.Status().Update(ctx, cp); err != nil {
		return ctrl.Result{}, err
	}
	metrics.ClusterManagedNamespaces.Set(float64(len(namespaces)))

	requeue := ttlQueue.MinDelay(defaultPollInterval)
	if cp.Spec.ResolutionTTLOverride != nil {
		requeue = clamp(time.Duration(*cp.Spec.ResolutionTTLOverride)*time.Second, ttlFloor, ttlCeiling)
	}
	return ctrl.Result{RequeueAfter: requeue}, nil
}

func findPreviousCluster(hosts []netv1alpha1.ResolvedHost, hostname string) *netv1alpha1.ResolvedHost {
	for i := range hosts {
		if hosts[i].Hostname == hostname {
			return &hosts[i]
		}
	}
	return nil
}

func (r *ClusterFQDNNetworkPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// Re-enqueue all ClusterFQDNNetworkPolicies whenever a namespace changes
	// so that NamespaceSelector membership is re-evaluated immediately.
	nsMapper := handler.EnqueueRequestsFromMapFunc(
		func(ctx context.Context, _ client.Object) []reconcile.Request {
			var list netv1alpha1.ClusterFQDNNetworkPolicyList
			if err := mgr.GetClient().List(ctx, &list); err != nil {
				return nil
			}
			reqs := make([]reconcile.Request, len(list.Items))
			for i, item := range list.Items {
				reqs[i] = reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&item)}
			}
			return reqs
		},
	)

	return ctrl.NewControllerManagedBy(mgr).
		For(&netv1alpha1.ClusterFQDNNetworkPolicy{}).
		Watches(&corev1.Namespace{}, nsMapper).
		Complete(r)
}
