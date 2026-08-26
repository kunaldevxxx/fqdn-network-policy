package dns

import (
	"context"
	"fmt"
)

// SnoopResolver will attach an eBPF probe (or read from a sidecar that does)
// to CoreDNS pods and build a live hostname->IP table from observed traffic,
// rather than issuing its own lookups. This is what makes the controller
// CNI-agnostic AND accurate for wildcard/CDN-backed hosts where active
// lookups can return a different IP than what a real pod received.
//
// Left unimplemented in this scaffold on purpose: get the reconcile loop
// and CRD contract solid against ActiveResolver first, then swap/add this
// implementation behind the same Resolver interface with no controller
// changes required.
type SnoopResolver struct {
	// e.g. a channel fed by a cilium/ebpf ring buffer reader attached to
	// the CoreDNS pods' network namespace, or an events endpoint exposed
	// by a small privileged DaemonSet doing the capture.
}

func NewSnoopResolver() *SnoopResolver {
	return &SnoopResolver{}
}

func (s *SnoopResolver) Resolve(ctx context.Context, hostname string) (Resolution, error) {
	return Resolution{}, fmt.Errorf("snoop resolver not yet implemented: see internal/dns/snoop_resolver.go")
}
