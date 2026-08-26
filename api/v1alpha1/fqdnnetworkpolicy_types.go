package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
	// Match is a hostname or a wildcard pattern, e.g. "api.stripe.com" or "*.googleapis.com".
	// +kubebuilder:validation:Required
	Match string `json:"match"`

	// Ports restricts the rule to specific destination ports/protocols.
	// Empty means all ports.
	// +optional
	Ports []PolicyPort `json:"ports,omitempty"`
}

// PolicyPort mirrors networkingv1.NetworkPolicyPort to avoid import coupling.
type PolicyPort struct {
	// Protocol is TCP, UDP, or SCTP. Defaults to TCP.
	// +optional
	// +kubebuilder:default=TCP
	Protocol string `json:"protocol,omitempty"`

	// Port is the destination port number.
	Port int32 `json:"port"`
}

// FQDNNetworkPolicySpec defines the desired state.
type FQDNNetworkPolicySpec struct {
	// PodSelector targets which pods in this namespace the rules apply to.
	PodSelector PodSelectorSpec `json:"podSelector"`

	// Egress is the list of allowed external FQDNs.
	Egress []FQDNRule `json:"egress"`

	// ResolutionTTLOverride forces a re-resolution interval in seconds,
	// overriding observed DNS TTLs. Useful for flaky upstream TTLs.
	// +optional
	ResolutionTTLOverride *int32 `json:"resolutionTTLOverride,omitempty"`
}

// ResolvedHost records the last known IPs for one matched hostname.
type ResolvedHost struct {
	Hostname   string      `json:"hostname"`
	IPs        []string    `json:"ips"`
	LastSeen   metav1.Time `json:"lastSeen"`
	Source     string      `json:"source"` // "dns-snoop" or "active-lookup"
}

// FQDNNetworkPolicyStatus defines the observed state.
type FQDNNetworkPolicyStatus struct {
	// ResolvedHosts is the current resolution cache backing the generated NetworkPolicy.
	// +optional
	ResolvedHosts []ResolvedHost `json:"resolvedHosts,omitempty"`

	// GeneratedNetworkPolicy is the name of the plain NetworkPolicy object
	// this controller manages on behalf of this resource.
	// +optional
	GeneratedNetworkPolicy string `json:"generatedNetworkPolicy,omitempty"`

	// Conditions follow the standard metav1.Condition pattern
	// (Ready, ResolutionDegraded, etc).
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// ObservedGeneration lets us detect stale status vs spec.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=fqdnnp,scope=Namespaced
// +kubebuilder:printcolumn:name="Generated",type=string,JSONPath=`.status.generatedNetworkPolicy`
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
