package profiler

import (
	"fmt"
	"sort"
	"time"

	netv1alpha1 "github.com/kunaldevxxx/fqdn-network-policy/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ProfileOptions configures policy synthesis from observed traffic.
type ProfileOptions struct {
	PolicyName        string
	Namespace         string
	PodSelector       map[string]string
	WildcardThreshold int
	Mode              netv1alpha1.PolicyMode
	SecurityPreset    string
	ObservedDomains   []netv1alpha1.ObservedDomain
	ObservationSource string
}

// ProfileSummary contains metrics and breakdown of the synthesized policy.
type ProfileSummary struct {
	TotalObserved       int
	InternalIgnored     int
	ExternalAllowed     int
	RulesGenerated      int
	WildcardsGenerated  int
	CategoryCounts      map[string]int
	WildcardRollupStats map[string][]string
}

// SynthesizePolicy transforms raw observed DNS domains into a hardened,
// production-ready FQDNNetworkPolicy.
func SynthesizePolicy(opts ProfileOptions) (*netv1alpha1.FQDNNetworkPolicy, *ProfileSummary, error) {
	if opts.PolicyName == "" {
		opts.PolicyName = "discovered-egress-policy"
	}
	if opts.Namespace == "" {
		opts.Namespace = "default"
	}
	if opts.Mode == "" {
		opts.Mode = netv1alpha1.PolicyModeAudit
	}
	if opts.WildcardThreshold <= 0 {
		opts.WildcardThreshold = 3
	}
	if opts.SecurityPreset == "" {
		opts.SecurityPreset = "production"
	}

	external, internal := FilterDomains(opts.ObservedDomains)

	domainNames := make([]string, 0, len(external))
	for _, d := range external {
		domainNames = append(domainNames, d.Hostname)
	}

	clusterRes := ClusterWildcards(domainNames, opts.WildcardThreshold)

	categoryCounts := make(map[string]int)
	egressRules := make([]netv1alpha1.FQDNRule, 0, len(clusterRes.Rules))

	for _, ruleMatch := range clusterRes.Rules {
		class := ClassifyDomain(ruleMatch)
		categoryCounts[class.Category]++

		egressRules = append(egressRules, netv1alpha1.FQDNRule{
			Match: ruleMatch,
			// Standard outbound web egress defaults to 443; omitted means all ports
			Ports: []netv1alpha1.PolicyPort{
				{Port: 443, Protocol: "TCP"},
			},
		})
	}

	// Security configuration presets
	sec := buildSecurityConfig(opts.SecurityPreset)

	labels := map[string]string{
		"app.kubernetes.io/managed-by": "kubectl-fqdn_policy",
		"netsec.kunal.dev/profiled":     "true",
	}

	annotations := map[string]string{
		"netsec.kunal.dev/profiled-at":                  time.Now().UTC().Format(time.RFC3339),
		"netsec.kunal.dev/profile-source":               opts.ObservationSource,
		"netsec.kunal.dev/profile-observed-count":       fmt.Sprintf("%d", len(opts.ObservedDomains)),
		"netsec.kunal.dev/profile-internal-count":       fmt.Sprintf("%d", len(internal)),
		"netsec.kunal.dev/profile-rules-count":          fmt.Sprintf("%d", len(clusterRes.Rules)),
		"netsec.kunal.dev/profile-wildcards-clustered":  fmt.Sprintf("%d", len(clusterRes.WildcardClusters)),
	}

	podLabels := opts.PodSelector
	if podLabels == nil {
		podLabels = map[string]string{}
	}

	policy := &netv1alpha1.FQDNNetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			APIVersion: netv1alpha1.GroupVersion.String(),
			Kind:       "FQDNNetworkPolicy",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:        opts.PolicyName,
			Namespace:   opts.Namespace,
			Labels:      labels,
			Annotations: annotations,
		},
		Spec: netv1alpha1.FQDNNetworkPolicySpec{
			PodSelector: netv1alpha1.PodSelectorSpec{
				PodSelector: metav1.LabelSelector{
					MatchLabels: podLabels,
				},
			},
			Egress:   egressRules,
			Mode:     opts.Mode,
			Security: sec,
		},
	}

	summary := &ProfileSummary{
		TotalObserved:       len(opts.ObservedDomains),
		InternalIgnored:     len(internal),
		ExternalAllowed:     len(external),
		RulesGenerated:      len(clusterRes.Rules),
		WildcardsGenerated:  len(clusterRes.WildcardClusters),
		CategoryCounts:      categoryCounts,
		WildcardRollupStats: clusterRes.WildcardClusters,
	}

	return policy, summary, nil
}

func buildSecurityConfig(preset string) *netv1alpha1.SecuritySpec {
	trueVal := true
	falseVal := false
	threeVal := int32(3)

	switch preset {
	case "strict":
		return &netv1alpha1.SecuritySpec{
			BlockPrivateIPs:      &trueVal,
			BlockOnDivergence:    &trueVal,
			MinResolverAgreement: &threeVal,
		}
	case "relaxed":
		return &netv1alpha1.SecuritySpec{
			BlockPrivateIPs:   &falseVal,
			BlockOnDivergence: &falseVal,
		}
	case "production":
		fallthrough
	default:
		return &netv1alpha1.SecuritySpec{
			BlockPrivateIPs:   &trueVal,
			BlockOnDivergence: &falseVal,
		}
	}
}

// PrintProfileSummary outputs a human-readable recap of the profiling result.
func (s *ProfileSummary) String() string {
	var categories []string
	for cat, count := range s.CategoryCounts {
		categories = append(categories, fmt.Sprintf("    - %s: %d rule(s)", cat, count))
	}
	sort.Strings(categories)

	catOutput := ""
	for _, line := range categories {
		catOutput += line + "\n"
	}

	wildcardOutput := ""
	if len(s.WildcardRollupStats) > 0 {
		wildcardOutput = "  Clustered Wildcards:\n"
		var wcKeys []string
		for k := range s.WildcardRollupStats {
			wcKeys = append(wcKeys, k)
		}
		sort.Strings(wcKeys)
		for _, k := range wcKeys {
			subs := s.WildcardRollupStats[k]
			wildcardOutput += fmt.Sprintf("    * %s (aggregated %d subdomains)\n", k, len(subs))
		}
	}

	return fmt.Sprintf(`Profile Summary:
  Total Observed Queries:   %d
  Internal Domains Filtered: %d
  External Candidates:      %d
  Generated Egress Rules:   %d
  Wildcards Aggregated:     %d
  Categories:
%s%s`, s.TotalObserved, s.InternalIgnored, s.ExternalAllowed, s.RulesGenerated, s.WildcardsGenerated, catOutput, wildcardOutput)
}
