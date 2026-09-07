package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// FQDNEgressObservationSpec configures passive discovery of hostnames
// resolved via DNS, so operators can write an FQDNNetworkPolicy without
// guessing. This is observation only -- it never writes a NetworkPolicy.
type FQDNEgressObservationSpec struct {
	// PodSelector is accepted for forward compatibility but is not yet
	// enforced: observations are cluster-wide, not scoped to this selector
	// or even to this namespace. CoreDNS's forward plugin re-originates
	// every forwarded query as its own client, so the snoop resolver can
	// never see which pod actually asked -- see
	// internal/dns/observation_store.go for why. Narrowing by pod/namespace
	// would need either a custom CoreDNS build or a different interception
	// mechanism (eBPF/iptables), both out of scope here.
	PodSelector PodSelectorSpec `json:"podSelector"`

	// ObservationWindow is how long to accumulate observations before the
	// result is considered stable (see status.observationComplete).
	// +optional
	// +kubebuilder:default="24h"
	ObservationWindow metav1.Duration `json:"observationWindow,omitempty"`
}

// ObservedDomain records one hostname observed cluster-wide via DNS.
type ObservedDomain struct {
	// Hostname is the FQDN observed in a DNS query.
	Hostname string `json:"hostname"`

	// FirstSeen is when this hostname was first observed.
	FirstSeen metav1.Time `json:"firstSeen"`

	// LastSeen is when this hostname was most recently observed.
	LastSeen metav1.Time `json:"lastSeen"`

	// ObservedPorts lists destination ports seen for this hostname.
	// Left empty until connection-level observation (beyond DNS snooping)
	// is available -- a follow-on feature.
	// +optional
	ObservedPorts []int32 `json:"observedPorts,omitempty"`
}

// FQDNEgressObservationStatus defines the observed state.
type FQDNEgressObservationStatus struct {
	// ObservedDomains is the accumulated set of hostnames seen cluster-wide
	// (see PodSelector's doc comment for why this isn't scoped further).
	// Additive across reconciles so data survives controller restarts.
	// +optional
	ObservedDomains []ObservedDomain `json:"observedDomains,omitempty"`

	// ObservationComplete is set once ObservationWindow has elapsed since
	// this resource was created.
	// +optional
	ObservationComplete bool `json:"observationComplete,omitempty"`

	// Conditions follow the standard metav1.Condition pattern.
	// Condition types: Ready, Degraded.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// ObservedGeneration lets us detect stale status vs spec.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=fqdneo,scope=Namespaced
// +kubebuilder:printcolumn:name="Complete",type=boolean,JSONPath=`.status.observationComplete`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// FQDNEgressObservation passively discovers hostnames queried anywhere in
// the cluster via the snoop resolver, to inform hand-written
// FQDNNetworkPolicy egress rules. It requires the snoop resolver to be
// active. Observations are cluster-wide, not scoped to PodSelector or this
// object's namespace -- see PodSelector's doc comment for why.
type FQDNEgressObservation struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   FQDNEgressObservationSpec   `json:"spec,omitempty"`
	Status FQDNEgressObservationStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// FQDNEgressObservationList contains a list of FQDNEgressObservation.
type FQDNEgressObservationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []FQDNEgressObservation `json:"items"`
}

func init() {
	SchemeBuilder.Register(&FQDNEgressObservation{}, &FQDNEgressObservationList{})
}
