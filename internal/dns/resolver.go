// Package dns provides pluggable hostname->IP resolution strategies.
//
// Two implementations are expected to exist side by side:
//   - activeResolver: standard DNS lookups on a timer, driven by TTL.
//     Simple, works everywhere, but can miss IPs that workloads actually
//     received if CoreDNS is load-balancing or caching differently than
//     the controller's own resolution path.
//   - snoopResolver (future): passively observes CoreDNS responses via
//     an eBPF probe attached to kube-dns/coredns pods, so the IP set
//     matches exactly what workloads resolved. This is the differentiator
//     described in the design doc; start with activeResolver to get the
//     control loop correct first.
package dns

import (
	"context"
	"net"
	"time"
)

// Resolution is one hostname's current answer set.
type Resolution struct {
	Hostname string
	IPs      []string
	// TTL is the minimum TTL observed across returned records, used to
	// schedule the next refresh. Zero means "use the default poll interval".
	TTL time.Time
}

// Resolver is implemented by every resolution strategy.
type Resolver interface {
	// Resolve returns the current best-known IPs for hostname.
	// hostname may contain a leading "*." wildcard; implementations that
	// can't expand wildcards (e.g. plain DNS) should return an error and
	// let the caller fall back or surface a status condition.
	Resolve(ctx context.Context, hostname string) (Resolution, error)
}

// ActiveResolver does plain DNS lookups using net.Resolver.
// It cannot resolve wildcard patterns; the reconciler is responsible for
// deciding what to do with those (e.g. require snoopResolver, or reject
// wildcard rules with a clear status condition rather than silently no-op).
type ActiveResolver struct {
	Net *net.Resolver
}

func NewActiveResolver() *ActiveResolver {
	return &ActiveResolver{Net: net.DefaultResolver}
}

func (a *ActiveResolver) Resolve(ctx context.Context, hostname string) (Resolution, error) {
	ips, err := a.Net.LookupIPAddr(ctx, hostname)
	if err != nil {
		return Resolution{}, err
	}
	res := Resolution{Hostname: hostname}
	for _, ip := range ips {
		res.IPs = append(res.IPs, ip.IP.String())
	}
	// net.Resolver doesn't expose TTL; default poll interval is applied
	// by the caller when TTL is zero-valued.
	return res, nil
}
