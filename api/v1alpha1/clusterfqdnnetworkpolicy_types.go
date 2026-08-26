package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ClusterFQDNNetworkPolicySpec defines cluster-wide FQDN egress rules.
// Platform teams use this to enforce baseline egress restrictions (e.g.
// telemetry, auth providers) across all or selected namespaces without
// duplicating FQDNNetworkPolicy in every namespace.
type ClusterFQDNNetworkPolicySpec struct {
	// NamespaceSelector selects which namespaces this policy applies to.
	// An empty selector means all namespaces.
	// +optional
	NamespaceSelector metav1.LabelSelector `json:"namespaceSelector,omitempty"`

	// PodSelector targets which pods within matched namespaces this policy applies to.
	// An empty selector means all pods.
	// +optional
	PodSelector PodSelectorSpec `json:"podSelector,omitempty"`

	// Egress is the list of allowed external FQDNs.
	// +kubebuilder:validation:MinItems=1
	Egress []FQDNRule `json:"egress"`

	// Mode controls enforcement. "Enforce" writes NetworkPolicy objects into
	// each matched namespace. "Audit" logs only.
	// +optional
	// +kubebuilder:default=Enforce
	Mode PolicyMode `json:"mode,omitempty"`

	// ResolutionTTLOverride forces a re-resolution interval in seconds.
	// +optional
	// +kubebuilder:validation:Minimum=5
	// +kubebuilder:validation:Maximum=300
	ResolutionTTLOverride *int32 `json:"resolutionTTLOverride,omitempty"`

	// CoreDNSAddress is the host:port of the cluster DNS server to query directly.
	// +optional
	CoreDNSAddress string `json:"coreDNSAddress,omitempty"`
}

// ClusterFQDNNetworkPolicyStatus defines the observed state.
type ClusterFQDNNetworkPolicyStatus struct {
	// ResolvedHosts is the current resolution cache.
	// +optional
	ResolvedHosts []ResolvedHost `json:"resolvedHosts,omitempty"`

	// AffectedNamespaces lists the namespaces where NetworkPolicy objects were generated.
	// +optional
	AffectedNamespaces []string `json:"affectedNamespaces,omitempty"`

	// Conditions follow the standard metav1.Condition pattern.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// ObservedGeneration lets us detect stale status vs spec.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=cfqdnnp,scope=Cluster
// +kubebuilder:printcolumn:name="Mode",type=string,JSONPath=`.spec.mode`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Namespaces",type=string,JSONPath=`.status.affectedNamespaces`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// ClusterFQDNNetworkPolicy enforces FQDN-based egress rules cluster-wide,
// generating per-namespace NetworkPolicy objects in all matched namespaces.
type ClusterFQDNNetworkPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ClusterFQDNNetworkPolicySpec   `json:"spec,omitempty"`
	Status ClusterFQDNNetworkPolicyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ClusterFQDNNetworkPolicyList contains a list of ClusterFQDNNetworkPolicy.
type ClusterFQDNNetworkPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ClusterFQDNNetworkPolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ClusterFQDNNetworkPolicy{}, &ClusterFQDNNetworkPolicyList{})
}
