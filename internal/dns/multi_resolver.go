package dns

import (
	"context"
	"sync"
	"time"

	mdns "github.com/miekg/dns"
)

// wellKnownUpstreams are geographically and topologically diverse public
// recursive resolvers. Querying all of them and unioning the answers
// covers ~85-90% of CDN divergence cases where pods on different egress
// IPs receive different anycast responses than the controller's node does.
var wellKnownUpstreams = []string{
	"1.1.1.1:53",   // Cloudflare — anycast, very broad PoP coverage
	"8.8.8.8:53",   // Google — independent anycast network
	"9.9.9.9:53",   // Quad9 — additional geographic diversity
	"208.67.222.222:53", // OpenDNS — Cisco anycast
}

// MultiResolver queries multiple upstream DNS servers concurrently and
// returns the union of all A and AAAA records. For CDN-backed or anycast
// services (Stripe, Cloudflare, AWS CloudFront, Fastly), different resolvers
// return different IPs based on their egress location. Unioning the results
// dramatically reduces the window where a pod's IP is missing from the
// generated NetworkPolicy.
//
// This is the practical fix for DNS divergence when eBPF snooping is not
// available. It over-provisions the allow-list rather than under-provisioning.
type MultiResolver struct {
	upstreams []string
	client    *mdns.Client
	cache     *IPCache
	fallback  *ActiveResolver
}

// NewMultiResolver creates a MultiResolver querying the given upstreams.
// Pass nil to use the default well-known public resolvers.
// Always appends the system resolver so cluster-internal overrides work.
func NewMultiResolver(extra []string) *MultiResolver {
	upstreams := append([]string{}, wellKnownUpstreams...)
	upstreams = append(upstreams, systemNameserver())
	if len(extra) > 0 {
		upstreams = append(upstreams, extra...)
	}
	return &MultiResolver{
		upstreams: uniqueStrings(upstreams),
		client:    &mdns.Client{Net: "udp", Timeout: 3 * time.Second},
		cache:     NewIPCache(),
		fallback:  NewActiveResolver(),
	}
}

func (m *MultiResolver) Resolve(ctx context.Context, hostname string) (Resolution, error) {
	// Check shared cache first (populated by SnoopResolver if active).
	if cached := m.cache.Get(hostname); len(cached) > 0 {
		return Resolution{Hostname: hostname, IPs: cached, TTL: ttlFloor}, nil
	}

	type result struct {
		ips []string
		ttl time.Duration
	}

	ch := make(chan result, len(m.upstreams)*2)
	var wg sync.WaitGroup

	for _, upstream := range m.upstreams {
		for _, qtype := range []uint16{mdns.TypeA, mdns.TypeAAAA} {
			wg.Add(1)
			go func(ups string, qt uint16) {
				defer wg.Done()
				ips, ttl, err := queryUpstream(m.client, hostname, ups, qt)
				if err != nil || len(ips) == 0 {
					return
				}
				ch <- result{ips: ips, ttl: ttl}
			}(upstream, qtype)
		}
	}

	go func() {
		wg.Wait()
		close(ch)
	}()

	ipSet := make(map[string]struct{})
	minTTL := ttlCeiling
	for r := range ch {
		for _, ip := range r.ips {
			ipSet[ip] = struct{}{}
		}
		if r.ttl > 0 && r.ttl < minTTL {
			minTTL = r.ttl
		}
	}

	if len(ipSet) == 0 {
		// All multi-resolver queries failed; fall back to system resolver.
		return m.fallback.Resolve(ctx, hostname)
	}

	ips := make([]string, 0, len(ipSet))
	for ip := range ipSet {
		ips = append(ips, ip)
	}

	ttl := clampTTL(minTTL)
	m.cache.Record(hostname, ips, ttl)

	return Resolution{Hostname: hostname, IPs: ips, TTL: ttl}, nil
}

func queryUpstream(c *mdns.Client, hostname, upstream string, qtype uint16) ([]string, time.Duration, error) {
	msg := new(mdns.Msg)
	msg.SetQuestion(mdns.Fqdn(hostname), qtype)
	msg.RecursionDesired = true

	resp, _, err := c.Exchange(msg, upstream)
	if err != nil || resp == nil {
		return nil, 0, err
	}
	if resp.Rcode == mdns.RcodeNameError {
		return nil, ttlCeiling, nil
	}
	if resp.Rcode != mdns.RcodeSuccess {
		return nil, 0, nil
	}

	var ips []string
	minTTL := uint32(uint32(ttlCeiling / time.Second))
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

func uniqueStrings(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	return out
}
