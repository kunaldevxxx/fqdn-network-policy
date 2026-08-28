package controller

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	netv1alpha1 "github.com/kunaldevxxx/fqdn-network-policy/api/v1alpha1"
	"github.com/kunaldevxxx/fqdn-network-policy/internal/dns"
	"github.com/kunaldevxxx/fqdn-network-policy/internal/metrics"
	"github.com/kunaldevxxx/fqdn-network-policy/internal/netpol"

	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	defaultPollInterval = 60 * time.Second
	ttlFloor            = 5 * time.Second
	ttlCeiling          = 300 * time.Second
)

// FQDNNetworkPolicyReconciler reconciles a FQDNNetworkPolicy object.
type FQDNNetworkPolicyReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Resolver dns.Resolver
	Recorder record.EventRecorder
}

// +kubebuilder:rbac:groups=netsec.kunal.dev,resources=fqdnnetworkpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=netsec.kunal.dev,resources=fqdnnetworkpolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=networking.k8s.io,resources=networkpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

func (r *FQDNNetworkPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var fp netv1alpha1.FQDNNetworkPolicy
	if err := r.Get(ctx, req.NamespacedName, &fp); err != nil {
		if apierrors.IsNotFound(err) {
			metrics.ManagedPolicies.Dec()
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	metrics.ManagedPolicies.Inc()

	ttlQueue := dns.NewTTLQueue()
	resolved := make([]netv1alpha1.ResolvedHost, 0, len(fp.Spec.Egress))
	var resolutionErrors []string

	for _, rule := range fp.Spec.Egress {
		if strings.Contains(rule.Match, "*") {
			resolutionErrors = append(resolutionErrors,
				"wildcard pattern \""+rule.Match+"\" requires the snoop resolver, skipping")
			continue
		}

		timer := time.Now()
		res, err := r.Resolver.Resolve(ctx, rule.Match)
		elapsed := time.Since(timer)
		metrics.DNSLookupDuration.WithLabelValues(rule.Match, "active").Observe(elapsed.Seconds())

		if err != nil {
			logger.Error(err, "resolution failed", "hostname", rule.Match)
			metrics.DNSLookupFailures.WithLabelValues(rule.Match, classifyError(err)).Inc()
			resolutionErrors = append(resolutionErrors, rule.Match+": "+err.Error())
			r.Recorder.Eventf(&fp, "Warning", "ResolutionFailed",
				"DNS lookup failed for %s: %v", rule.Match, err)
			// Retain the previous resolution to avoid dropping egress on a transient DNS blip.
			if prev := findPrevious(fp.Status.ResolvedHosts, rule.Match); prev != nil {
				resolved = append(resolved, *prev)
				ttlQueue.Upsert(rule.Match, defaultPollInterval)
			}
			continue
		}

		ttl := res.TTL
		if ttl == 0 {
			ttl = defaultPollInterval
		}
		ttlQueue.Upsert(rule.Match, ttl)
		metrics.ResolvedIPsCount.WithLabelValues(rule.Match).Set(float64(len(res.IPs)))

		resolved = append(resolved, netv1alpha1.ResolvedHost{
			Hostname:   rule.Match,
			IPs:        res.IPs,
			CNAMEChain: res.CNAMEChain,
			LastSeen:   metav1.Now(),
			Source:     "active-lookup",
			TTLSeconds: int32(ttl.Seconds()),
		})

		if fp.Spec.Security != nil && fp.Spec.Security.MaxCNAMEDepth != nil {
			if maxDepth := int(*fp.Spec.Security.MaxCNAMEDepth); maxDepth > 0 && len(res.CNAMEChain) > maxDepth {
				resolutionErrors = append(resolutionErrors,
					fmt.Sprintf("%s: CNAME chain depth %d exceeds maxCNAMEDepth %d",
						rule.Match, len(res.CNAMEChain), maxDepth))
			}
		}
	}

	// Audit mode: log only, no NetworkPolicy writes.
	if fp.Spec.Mode == netv1alpha1.PolicyModeAudit {
		logger.Info("audit mode: resolved hosts (no NetworkPolicy written)",
			"policy", fp.Name, "hosts", resolved)
		r.Recorder.Event(&fp, "Normal", "AuditResolved",
			"Audit mode: resolved FQDNs without writing NetworkPolicy")
		fp.Status.ResolvedHosts = resolved
		fp.Status.GeneratedNetworkPolicy = ""
		fp.Status.ObservedGeneration = fp.Generation
		setCondition(&fp, "Ready", metav1.ConditionTrue, "AuditMode",
			"Audit mode active; no NetworkPolicy generated")
		if err := r.Status().Update(ctx, &fp); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: nextRequeue(&fp, ttlQueue)}, nil
	}

	// Enforce mode: build and conditionally apply the NetworkPolicy.
	fp.Status.ResolvedHosts = resolved
	desired, err := netpol.Build(&fp)
	if err != nil {
		return ctrl.Result{}, err
	}

	if err := r.applyNetworkPolicy(ctx, &fp, desired); err != nil {
		r.Recorder.Eventf(&fp, "Warning", "SyncFailed",
			"Failed to sync NetworkPolicy %s: %v", desired.Name, err)
		return ctrl.Result{}, err
	}

	fp.Status.GeneratedNetworkPolicy = desired.Name
	fp.Status.ObservedGeneration = fp.Generation
	setReadyCondition(&fp, resolutionErrors)

	if err := r.Status().Update(ctx, &fp); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{RequeueAfter: nextRequeue(&fp, ttlQueue)}, nil
}

// applyNetworkPolicy creates or updates the NetworkPolicy only when the IP set
// has actually changed, preventing unnecessary etcd writes and CNI dataplane reloads.
func (r *FQDNNetworkPolicyReconciler) applyNetworkPolicy(
	ctx context.Context,
	fp *netv1alpha1.FQDNNetworkPolicy,
	desired *networkingv1.NetworkPolicy,
) error {
	logger := log.FromContext(ctx)

	var existing networkingv1.NetworkPolicy
	err := r.Get(ctx, client.ObjectKeyFromObject(desired), &existing)
	switch {
	case apierrors.IsNotFound(err):
		r.Recorder.Eventf(fp, "Normal", "NetworkPolicyCreated",
			"Created NetworkPolicy %s", desired.Name)
		return r.Create(ctx, desired)

	case err != nil:
		return err

	default:
		if ipSetsEqual(existing.Spec.Egress, desired.Spec.Egress) {
			logger.V(1).Info("resolved IPs unchanged, skipping NetworkPolicy update",
				"policy", desired.Name)
			return nil
		}
		existing.Spec = desired.Spec
		existing.Labels = desired.Labels
		r.Recorder.Eventf(fp, "Normal", "NetworkPolicyUpdated",
			"Updated NetworkPolicy %s with new IP set", desired.Name)
		return r.Update(ctx, &existing)
	}
}

// ipSetsEqual compares the IP sets across two sets of egress rules.
// Returns true when the effective CIDR lists are identical (order-independent).
func ipSetsEqual(a, b []networkingv1.NetworkPolicyEgressRule) bool {
	extract := func(rules []networkingv1.NetworkPolicyEgressRule) []string {
		var cidrs []string
		for _, rule := range rules {
			for _, peer := range rule.To {
				if peer.IPBlock != nil {
					cidrs = append(cidrs, peer.IPBlock.CIDR)
				}
			}
		}
		sort.Strings(cidrs)
		return cidrs
	}
	return slices.Equal(extract(a), extract(b))
}

// nextRequeue returns the RequeueAfter interval: spec override > TTL queue min > default.
func nextRequeue(fp *netv1alpha1.FQDNNetworkPolicy, q *dns.TTLQueue) time.Duration {
	if fp.Spec.ResolutionTTLOverride != nil {
		d := time.Duration(*fp.Spec.ResolutionTTLOverride) * time.Second
		return clamp(d, ttlFloor, ttlCeiling)
	}
	return q.MinDelay(defaultPollInterval)
}

func clamp(d, floor, ceiling time.Duration) time.Duration {
	if d < floor {
		return floor
	}
	if d > ceiling {
		return ceiling
	}
	return d
}

func findPrevious(hosts []netv1alpha1.ResolvedHost, hostname string) *netv1alpha1.ResolvedHost {
	for i := range hosts {
		if hosts[i].Hostname == hostname {
			return &hosts[i]
		}
	}
	return nil
}

func classifyError(err error) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "no such host") || strings.Contains(msg, "NXDOMAIN"):
		return "nxdomain"
	case strings.Contains(msg, "timeout") || strings.Contains(msg, "i/o timeout"):
		return "timeout"
	case strings.Contains(msg, "SERVFAIL"):
		return "servfail"
	default:
		return "other"
	}
}

func setReadyCondition(fp *netv1alpha1.FQDNNetworkPolicy, resolutionErrors []string) {
	if len(resolutionErrors) > 0 {
		setCondition(fp, "Ready", metav1.ConditionFalse, "ResolutionDegraded",
			strings.Join(resolutionErrors, "; "))
		setCondition(fp, "Degraded", metav1.ConditionTrue, "ResolutionErrors",
			strings.Join(resolutionErrors, "; "))
		return
	}
	setCondition(fp, "Ready", metav1.ConditionTrue, "Reconciled",
		"NetworkPolicy generated from resolved hosts")
	setCondition(fp, "Degraded", metav1.ConditionFalse, "OK", "")
}

func setCondition(fp *netv1alpha1.FQDNNetworkPolicy, condType string, status metav1.ConditionStatus, reason, msg string) {
	cond := metav1.Condition{
		Type:               condType,
		Status:             status,
		Reason:             reason,
		Message:            msg,
		ObservedGeneration: fp.Generation,
		LastTransitionTime: metav1.Now(),
	}
	for i, c := range fp.Status.Conditions {
		if c.Type == condType {
			if c.Status == status {
				// Preserve LastTransitionTime when status hasn't changed.
				cond.LastTransitionTime = c.LastTransitionTime
			}
			fp.Status.Conditions[i] = cond
			return
		}
	}
	fp.Status.Conditions = append(fp.Status.Conditions, cond)
}

func (r *FQDNNetworkPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&netv1alpha1.FQDNNetworkPolicy{}).
		Owns(&networkingv1.NetworkPolicy{}).
		Complete(r)
}

var _ = controllerutil.SetControllerReference
