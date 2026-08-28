package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// PolicyMode controls whether the controller enforces the generated
// NetworkPolicy or only logs what would have been allowed/blocked.
// +kubebuilder:validation:Enum=Enforce;Audit
type PolicyMode string

const (
	PolicyModeEnforce PolicyMode = "Enforce"
	PolicyModeAudit   PolicyMode = "Audit"
)

// PodSelectorSpec mirrors the subset of NetworkPolicy's pod/namespace targeting
// that we need. Kept separate from networkingv1 types so this CRD has no hard
// dependency on how the generated NetworkPolicy is shaped downstream.
type PodSelectorSpec struct {
	// PodSelector selects the pods this policy applies to within the namespace.
	// Empty selector means "all pods in the namespace".
	// +optional
	PodSelector metav1.LabelSelector `json:"podSelector,omitempty"`
}

// FQDNRule describes one allowed external destination.
type FQDNRule struct {
	// Match is a fully qualified domain name, e.g. "api.stripe.com".
	// Wildcard patterns (*.foo.com) are accepted only when the snoop resolver
	// is active; a validation webhook rejects wildcards otherwise.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:XValidation:rule="self.matches('^(\\\\*\\\\.)?([a-zA-Z0-9]([a-zA-Z0-9\\\\-]{0,61}[a-zA-Z0-9])?\\\\.)+[a-zA-Z]{2,}$')",message="Must be a valid FQDN or wildcard FQDN (*.example.com)."
	Match string `json:"match"`

	// Ports restricts the rule to specific destination ports/protocols.
	// Empty means all ports. Specifying explicit ports is strongly recommended
	// to avoid opening attack vectors on unintended port numbers.
	// +optional
	Ports []PolicyPort `json:"ports,omitempty"`
}

// PolicyPort mirrors networkingv1.NetworkPolicyPort to avoid import coupling.
type PolicyPort struct {
	// Protocol is TCP, UDP, or SCTP. Defaults to TCP.
	// +optional
	// +kubebuilder:default=TCP
	// +kubebuilder:validation:Enum=TCP;UDP;SCTP
	Protocol string `json:"protocol,omitempty"`

	// Port is the destination port number (1-65535).
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Port int32 `json:"port"`
}

// FQDNNetworkPolicySpec defines the desired state.
type FQDNNetworkPolicySpec struct {
	// PodSelector targets which pods in this namespace the rules apply to.
	PodSelector PodSelectorSpec `json:"podSelector"`

	// Egress is the list of allowed external FQDNs.
	// +kubebuilder:validation:MinItems=1
	Egress []FQDNRule `json:"egress"`

	// Mode controls enforcement. "Enforce" (default) creates and maintains
	// the generated NetworkPolicy. "Audit" logs what would be allowed/blocked
	// without writing any NetworkPolicy -- safe for dry-runs.
	// +optional
	// +kubebuilder:default=Enforce
	Mode PolicyMode `json:"mode,omitempty"`

	// ResolutionTTLOverride forces a re-resolution interval in seconds,
	// overriding observed DNS TTLs. Useful for flaky upstream TTLs.
	// +optional
	// +kubebuilder:validation:Minimum=5
	// +kubebuilder:validation:Maximum=300
	ResolutionTTLOverride *int32 `json:"resolutionTTLOverride,omitempty"`

	// CoreDNSAddress is the host:port of the cluster DNS server to query
	// directly (e.g. "10.96.0.10:53"). When set, the controller resolves
	// FQDNs against cluster CoreDNS rather than the node's system resolver,
	// reducing geo-DNS divergence between the controller and workload pods.
	// +optional
	CoreDNSAddress string `json:"coreDNSAddress,omitempty"`

	// Security defines security-related constraints on FQDN resolution.
	// +optional
	Security *SecuritySpec `json:"security,omitempty"`
}

// SecuritySpec defines security-related constraints on FQDN resolution.
type SecuritySpec struct {
	// MaxCNAMEDepth is the maximum allowed CNAME chain length before the
	// controller raises a Degraded condition. 0 or unset means no limit.
	// +optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=10
	MaxCNAMEDepth *int32 `json:"maxCNAMEDepth,omitempty"`
}

// ResolvedHost records the last known IPs for one matched hostname.
type ResolvedHost struct {
	Hostname string      `json:"hostname"`
	IPs      []string    `json:"ips"`
	LastSeen metav1.Time `json:"lastSeen"`
	// Source is "dns-snoop" when the eBPF resolver observed the answer, or
	// "active-lookup" when the controller queried DNS directly.
	Source string `json:"source"`
	// TTLSeconds is the DNS TTL of the last response, in seconds.
	// +optional
	TTLSeconds int32 `json:"ttlSeconds,omitempty"`
	// CNAMEChain holds the ordered CNAME targets from the queried hostname to
	// the final canonical name. Empty when the name resolved without CNAME indirection.
	// +optional
	CNAMEChain []string `json:"cnameChain,omitempty"`
}

// FQDNNetworkPolicyStatus defines the observed state.
type FQDNNetworkPolicyStatus struct {
	// ResolvedHosts is the current resolution cache backing the generated NetworkPolicy.
	// +optional
	ResolvedHosts []ResolvedHost `json:"resolvedHosts,omitempty"`

	// GeneratedNetworkPolicy is the name of the plain NetworkPolicy object
	// this controller manages on behalf of this resource.
	// Empty in Audit mode (no NetworkPolicy is written).
	// +optional
	GeneratedNetworkPolicy string `json:"generatedNetworkPolicy,omitempty"`

	// Conditions follow the standard metav1.Condition pattern.
	// Condition types: Ready, Resolving, Degraded.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// ObservedGeneration lets us detect stale status vs spec.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=fqdnnp,scope=Namespaced
// +kubebuilder:printcolumn:name="Mode",type=string,JSONPath=`.spec.mode`
// +kubebuilder:printcolumn:name="Generated",type=string,JSONPath=`.status.generatedNetworkPolicy`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// FQDNNetworkPolicy lets users allow-list egress by hostname on any CNI,
// by resolving hostnames to IPs and reconciling a standard NetworkPolicy.
type FQDNNetworkPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   FQDNNetworkPolicySpec   `json:"spec,omitempty"`
	Status FQDNNetworkPolicyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// FQDNNetworkPolicyList contains a list of FQDNNetworkPolicy.
type FQDNNetworkPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []FQDNNetworkPolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&FQDNNetworkPolicy{}, &FQDNNetworkPolicyList{})
}
