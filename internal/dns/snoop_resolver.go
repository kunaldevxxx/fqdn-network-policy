// Package dns - SnoopResolver implements a recording DNS forwarding proxy.
//
// Architecture:
//
//	Pod → CoreDNS → [SnoopResolver proxy :5353] → Upstream DNS
//	                        ↓
//	              IPCache (hostname → observed IPs)
//	                        ↓
//	              Reconciler reads live IPs per domain
//
// The operator configures CoreDNS to forward all queries to the controller's
// snoop proxy address, so the proxy sees every DNS response flowing to pods.
// This is the only approach that gives exactly the IPs pods received without
// requiring eBPF or host-level packet capture.
//
// CoreDNS ConfigMap snippet to enable:
//
//	.:53 {
//	    forward . 10.96.0.10:5353  # controller snoop proxy address
//	    cache 30
//	}
package dns

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	mdns "github.com/miekg/dns"
)

const (
	defaultSnoopPort    = "5353"
	defaultPollInterval = 60 * time.Second
)

// SnoopResolver is a recording DNS forwarding proxy. It satisfies the
// Resolver interface so it can be wired into the reconciler identically
// to ActiveResolver. Additionally it runs a local miekg/dns server that
// intercepts queries, records all A/AAAA answers into IPCache, and
// forwards each query to the real upstream.
type SnoopResolver struct {
	cache    *IPCache
	upstream string
	server   *mdns.Server
	multi    *MultiResolver // fallback for Resolve() on cache miss
	mu       sync.RWMutex
	ready    bool
}

// NewSnoopResolver creates a SnoopResolver that listens on listenAddr
// (e.g. "0.0.0.0:5353") and forwards queries to upstream (e.g. "10.96.0.10:53").
// Call Start(ctx) to begin accepting connections.
func NewSnoopResolver(listenAddr, upstream string) *SnoopResolver {
	if listenAddr == "" {
		listenAddr = "0.0.0.0:" + defaultSnoopPort
	}
	if upstream == "" {
		upstream = systemNameserver()
	}
	sr := &SnoopResolver{
		cache:    NewIPCache(),
		upstream: upstream,
		multi:    NewMultiResolver([]string{upstream}),
	}
	mux := mdns.NewServeMux()
	mux.HandleFunc(".", sr.handleQuery)
	sr.server = &mdns.Server{
		Addr:    listenAddr,
		Net:     "udp",
		Handler: mux,
	}
	return sr
}

// Start launches the DNS proxy server in the background.
// It blocks until the server is ready or ctx is cancelled.
func (s *SnoopResolver) Start(ctx context.Context) error {
	errCh := make(chan error, 1)
	go func() {
		if err := s.server.ListenAndServe(); err != nil {
			errCh <- fmt.Errorf("snoop DNS proxy: %w", err)
		}
	}()

	// Wait briefly for the server to bind.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if isListening(s.server.Addr) {
			s.mu.Lock()
			s.ready = true
			s.mu.Unlock()
			return nil
		}
		select {
		case err := <-errCh:
			return err
		case <-time.After(50 * time.Millisecond):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return fmt.Errorf("snoop DNS proxy did not become ready on %s within 2s", s.server.Addr)
}

// Shutdown stops the DNS proxy server gracefully.
func (s *SnoopResolver) Shutdown() {
	_ = s.server.Shutdown()
}

// Resolve implements dns.Resolver. It returns the union of IPs this proxy
// has observed for hostname plus any additional IPs from the multi-resolver
// (which also queries multiple upstream vantage points).
func (s *SnoopResolver) Resolve(ctx context.Context, hostname string) (Resolution, error) {
	observed := s.cache.Get(hostname)

	// Always also run MultiResolver to catch IPs the proxy hasn't seen yet
	// (e.g. before any pod has queried this host since startup).
	active, err := s.multi.Resolve(ctx, hostname)
	if err != nil && len(observed) == 0 {
		return Resolution{}, err
	}

	combined := unionIPs(observed, active.IPs)
	ttl := active.TTL
	if ttl == 0 {
		ttl = defaultPollInterval
	}

	return Resolution{
		Hostname: hostname,
		IPs:      combined,
		TTL:      ttl,
	}, nil
}

// handleQuery processes an incoming DNS query from CoreDNS, forwards it to
// the real upstream, records observed A/AAAA records, and writes the response.
func (s *SnoopResolver) handleQuery(w mdns.ResponseWriter, req *mdns.Msg) {
	upstream := s.upstream
	client := &mdns.Client{Net: "udp", Timeout: 5 * time.Second}

	resp, _, err := client.Exchange(req, upstream)
	if err != nil || resp == nil {
		// Return SERVFAIL rather than dropping the query.
		fail := new(mdns.Msg)
		fail.SetReply(req)
		fail.Rcode = mdns.RcodeServerFailure
		_ = w.WriteMsg(fail)
		return
	}

	// Record every A and AAAA record we observe.
	for _, q := range req.Question {
		hostname := mdns.Fqdn(q.Name)
		// Trim trailing dot for consistency with the rest of the controller.
		if len(hostname) > 0 && hostname[len(hostname)-1] == '.' {
			hostname = hostname[:len(hostname)-1]
		}

		var ips []string
		minTTL := uint32(300)
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

		if len(ips) > 0 {
			s.cache.Record(hostname, ips, time.Duration(minTTL)*time.Second)
		}
	}

	_ = w.WriteMsg(resp)
}

// isListening probes whether addr is accepting UDP connections.
func isListening(addr string) bool {
	conn, err := net.DialTimeout("udp", addr, 200*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// unionIPs returns a deduplicated union of two IP slices.
func unionIPs(a, b []string) []string {
	seen := make(map[string]struct{}, len(a)+len(b))
	result := make([]string, 0, len(a)+len(b))
	for _, ip := range append(a, b...) {
		if _, ok := seen[ip]; !ok {
			seen[ip] = struct{}{}
			result = append(result, ip)
		}
	}
	return result
}
