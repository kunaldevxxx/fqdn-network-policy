// Package dns provides pluggable hostname->IP resolution strategies.
//
// Two implementations exist side by side:
//   - ActiveResolver: TTL-aware A+AAAA lookups via miekg/dns, with optional
//     CoreDNS direct querying to match what pods actually receive.
//   - SnoopResolver (future): passively observes CoreDNS responses via eBPF.
package dns

import (
	"context"
	"fmt"
	"net"
	"time"

	mdns "github.com/miekg/dns"
)

const (
	ttlFloor   = 5 * time.Second
	ttlCeiling = 300 * time.Second
)

// Resolution is one hostname's current answer set.
type Resolution struct {
	Hostname string
	IPs      []string
	// TTL is the clamped minimum TTL across all returned records.
	// Zero means "use the default poll interval".
	TTL time.Duration
}

// Resolver is implemented by every resolution strategy.
type Resolver interface {
	// Resolve returns the current best-known IPs for hostname.
	// Wildcard patterns (*.foo.com) should return an error for implementations
	// that can't expand them (e.g. plain DNS).
	Resolve(ctx context.Context, hostname string) (Resolution, error)
}

// ActiveResolver does TTL-aware A and AAAA lookups using miekg/dns.
// It can optionally target a specific nameserver (e.g. cluster CoreDNS)
// to mirror what pods receive rather than what the controller node resolves.
type ActiveResolver struct {
	// Nameserver is host:port of the DNS server to query.
	// Defaults to the system resolver from /etc/resolv.conf.
	Nameserver string
	client     *mdns.Client
}

func NewActiveResolver() *ActiveResolver {
	return &ActiveResolver{
		Nameserver: systemNameserver(),
		client:     &mdns.Client{Net: "udp"},
	}
}

// NewCoreDNSResolver returns an ActiveResolver that queries the cluster's
// CoreDNS directly (kube-dns service address), reducing geo-DNS divergence
// between the controller node and workload pods.
func NewCoreDNSResolver(coreDNSAddr string) *ActiveResolver {
	return &ActiveResolver{
		Nameserver: coreDNSAddr,
		client:     &mdns.Client{Net: "udp"},
	}
}

func (a *ActiveResolver) Resolve(ctx context.Context, hostname string) (Resolution, error) {
	if hostname == "" {
		return Resolution{}, fmt.Errorf("empty hostname")
	}

	// Resolve A and AAAA concurrently.
	type result struct {
		ips []string
		ttl time.Duration
		err error
	}
	ch := make(chan result, 2)

	for _, qtype := range []uint16{mdns.TypeA, mdns.TypeAAAA} {
		go func(qt uint16) {
			ips, ttl, err := a.query(hostname, qt)
			ch <- result{ips: ips, ttl: ttl, err: err}
		}(qtype)
	}

	res := Resolution{Hostname: hostname}
	minTTL := ttlCeiling
	var errs []error

	for range 2 {
		r := <-ch
		if r.err != nil {
			errs = append(errs, r.err)
			continue
		}
		res.IPs = append(res.IPs, r.ips...)
		if r.ttl < minTTL {
			minTTL = r.ttl
		}
	}

	if len(res.IPs) == 0 {
		if len(errs) > 0 {
			return Resolution{}, errs[0]
		}
		return Resolution{}, fmt.Errorf("no A or AAAA records for %s", hostname)
	}

	res.TTL = clampTTL(minTTL)
	return res, nil
}

func (a *ActiveResolver) query(hostname string, qtype uint16) ([]string, time.Duration, error) {
	fqdn := mdns.Fqdn(hostname)
	msg := new(mdns.Msg)
	msg.SetQuestion(fqdn, qtype)
	msg.RecursionDesired = true

	resp, _, err := a.client.Exchange(msg, a.Nameserver)
	if err != nil {
		// Fall back to system resolver for this record type; TTL unknown.
		return a.fallbackLookup(hostname, qtype)
	}
	if resp.Rcode != mdns.RcodeSuccess {
		// NXDOMAIN or SERVFAIL for this record type is not fatal (e.g. an
		// IPv4-only host returns NXDOMAIN for AAAA); return empty.
		if resp.Rcode == mdns.RcodeNameError {
			return nil, ttlCeiling, nil
		}
		return nil, 0, fmt.Errorf("DNS rcode %s for %s type %d", mdns.RcodeToString[resp.Rcode], hostname, qtype)
	}

	var ips []string
	minTTL := uint32(ttlCeiling / time.Second)
	for _, rr := range resp.Answer {
		switch v := rr.(type) {
		case *mdns.A:
			ips = append(ips, v.A.String())
			if v.Hdr.Ttl < minTTL {
				minTTL = v.Hdr.Ttl
			}
		case *mdns.AAAA:
			ips = append(ips, v.AAAA.String())
			if v.Hdr.Ttl < minTTL {
				minTTL = v.Hdr.Ttl
			}
		}
	}
	return ips, time.Duration(minTTL) * time.Second, nil
}

// fallbackLookup uses net.DefaultResolver when the miekg exchange fails.
// TTL is unknown in this path, so we return 0 to signal "use default".
func (a *ActiveResolver) fallbackLookup(hostname string, qtype uint16) ([]string, time.Duration, error) {
	addrs, err := net.DefaultResolver.LookupIPAddr(context.Background(), hostname)
	if err != nil {
		return nil, 0, err
	}
	var ips []string
	for _, addr := range addrs {
		isIPv6 := addr.IP.To4() == nil
		if qtype == mdns.TypeA && !isIPv6 {
			ips = append(ips, addr.IP.String())
		} else if qtype == mdns.TypeAAAA && isIPv6 {
			ips = append(ips, addr.IP.String())
		}
	}
	return ips, 0, nil
}

func clampTTL(d time.Duration) time.Duration {
	if d < ttlFloor {
		return ttlFloor
	}
	if d > ttlCeiling {
		return ttlCeiling
	}
	return d
}

// systemNameserver reads the first nameserver from /etc/resolv.conf.
// Returns "8.8.8.8:53" as a safe fallback.
func systemNameserver() string {
	cfg, err := mdns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil || len(cfg.Servers) == 0 {
		return "8.8.8.8:53"
	}
	return net.JoinHostPort(cfg.Servers[0], cfg.Port)
}
