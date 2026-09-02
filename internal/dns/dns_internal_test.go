package dns

import (
	"container/heap"
	"context"
	"net"
	"strings"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── Test helpers ───────────────────────────────────────────────────────────

// startMockDNS starts a local UDP DNS server that returns static answers.
// answers maps bare hostname (no trailing dot) → IP strings.
func startMockDNS(t *testing.T, answers map[string][]string) (addr string, stop func()) {
	t.Helper()
	mux := mdns.NewServeMux()
	mux.HandleFunc(".", func(w mdns.ResponseWriter, req *mdns.Msg) {
		resp := new(mdns.Msg)
		resp.SetReply(req)
		for _, q := range req.Question {
			hostname := strings.TrimSuffix(q.Name, ".")
			ips, ok := answers[hostname]
			if !ok {
				resp.Rcode = mdns.RcodeNameError
				_ = w.WriteMsg(resp)
				return
			}
			for _, rawIP := range ips {
				parsed := net.ParseIP(rawIP)
				if parsed == nil {
					continue
				}
				if v4 := parsed.To4(); v4 != nil && q.Qtype == mdns.TypeA {
					resp.Answer = append(resp.Answer, &mdns.A{
						Hdr: mdns.RR_Header{Name: q.Name, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 60},
						A:   v4,
					})
				} else if parsed.To4() == nil && q.Qtype == mdns.TypeAAAA {
					resp.Answer = append(resp.Answer, &mdns.AAAA{
						Hdr: mdns.RR_Header{Name: q.Name, Rrtype: mdns.TypeAAAA, Class: mdns.ClassINET, Ttl: 60},
						AAAA: parsed,
					})
				}
			}
		}
		_ = w.WriteMsg(resp)
	})

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	serverAddr := pc.LocalAddr().String()

	srv := &mdns.Server{PacketConn: pc, Net: "udp", Handler: mux}
	ready := make(chan struct{})
	srv.NotifyStartedFunc = func() { close(ready) }
	go func() { _ = srv.ActivateAndServe() }()

	select {
	case <-ready:
	case <-time.After(2 * time.Second):
		t.Fatal("mock DNS server did not start within 2s")
	}
	return serverAddr, func() { _ = srv.Shutdown() }
}

// freeUDPAddr returns a 127.0.0.1:port string whose port was free at call time.
// With NotifyStartedFunc in SnoopResolver.Start, the server blocks until it
// has actually bound -- so by the time Start returns the port is in use and
// there is no observable race for the test client.
func freeUDPAddr(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := pc.LocalAddr().String()
	_ = pc.Close()
	return addr
}

// mockMultiResolver builds a MultiResolver that queries only the given addr.
func mockMultiResolver(addr string) *MultiResolver {
	return &MultiResolver{
		upstreams: []string{addr},
		client:    &mdns.Client{Net: "udp", Timeout: 3 * time.Second},
		cache:     NewIPCache(),
		fallback:  NewActiveResolver(),
	}
}

// ── clampTTL ───────────────────────────────────────────────────────────────

func TestClampTTL_BelowFloor(t *testing.T) {
	assert.Equal(t, ttlFloor, clampTTL(0))
	assert.Equal(t, ttlFloor, clampTTL(1*time.Second))
}

func TestClampTTL_InRange(t *testing.T) {
	assert.Equal(t, 30*time.Second, clampTTL(30*time.Second))
}

func TestClampTTL_AboveCeiling(t *testing.T) {
	assert.Equal(t, ttlCeiling, clampTTL(10*time.Minute))
}

// ── unionIPs ───────────────────────────────────────────────────────────────

func TestUnionIPs_Combines(t *testing.T) {
	got := unionIPs([]string{"1.1.1.1"}, []string{"2.2.2.2"})
	assert.ElementsMatch(t, []string{"1.1.1.1", "2.2.2.2"}, got)
}

func TestUnionIPs_Deduplicates(t *testing.T) {
	got := unionIPs([]string{"1.1.1.1"}, []string{"1.1.1.1"})
	assert.ElementsMatch(t, []string{"1.1.1.1"}, got)
}

func TestUnionIPs_NilInputs(t *testing.T) {
	assert.Empty(t, unionIPs(nil, nil))
}

func TestUnionIPs_OneNil(t *testing.T) {
	assert.ElementsMatch(t, []string{"1.1.1.1"}, unionIPs([]string{"1.1.1.1"}, nil))
}

// ── TTLQueue: Swap and Pop ─────────────────────────────────────────────────

func TestTTLQueue_SwapOnHeapify(t *testing.T) {
	q := NewTTLQueue()
	// Inserting a shorter TTL after a longer one forces a bubble-up (Swap).
	q.Upsert("slow.example.com", 60*time.Second)
	q.Upsert("fast.example.com", 5*time.Second)
	// Swap must have run correctly: min element is now "fast".
	assert.Equal(t, "fast.example.com", q.items[0].Hostname)
}

func TestTTLQueue_Pop(t *testing.T) {
	q := NewTTLQueue()
	q.Upsert("fast.example.com", 5*time.Second)
	q.Upsert("slow.example.com", 60*time.Second)

	got := heap.Pop(q).(*TTLEntry)
	assert.Equal(t, "fast.example.com", got.Hostname)
	assert.Equal(t, 1, q.Len())
}

// ── queryUpstream ──────────────────────────────────────────────────────────

func TestQueryUpstream_IPv4(t *testing.T) {
	addr, stop := startMockDNS(t, map[string][]string{
		"api.example.com": {"1.2.3.4"},
	})
	defer stop()

	c := &mdns.Client{Net: "udp", Timeout: 3 * time.Second}
	ips, _, ttl, _, err := queryUpstream(c, "api.example.com", addr, mdns.TypeA)
	require.NoError(t, err)
	assert.Equal(t, []string{"1.2.3.4"}, ips)
	assert.Greater(t, ttl, time.Duration(0))
}

func TestQueryUpstream_IPv6(t *testing.T) {
	addr, stop := startMockDNS(t, map[string][]string{
		"api.example.com": {"2001:db8::1"},
	})
	defer stop()

	c := &mdns.Client{Net: "udp", Timeout: 3 * time.Second}
	ips, _, _, _, err := queryUpstream(c, "api.example.com", addr, mdns.TypeAAAA)
	require.NoError(t, err)
	assert.Equal(t, []string{"2001:db8::1"}, ips)
}

func TestQueryUpstream_NXDOMAIN(t *testing.T) {
	addr, stop := startMockDNS(t, map[string][]string{})
	defer stop()

	c := &mdns.Client{Net: "udp", Timeout: 3 * time.Second}
	ips, _, _, _, err := queryUpstream(c, "unknown.example.com", addr, mdns.TypeA)
	require.NoError(t, err)
	assert.Empty(t, ips)
}

// ── NewCoreDNSResolver ─────────────────────────────────────────────────────

func TestNewCoreDNSResolver(t *testing.T) {
	r := NewCoreDNSResolver("10.96.0.10:53")
	require.NotNil(t, r)
	assert.Equal(t, "10.96.0.10:53", r.Nameserver)
}

// ── MultiResolver ──────────────────────────────────────────────────────────

func TestMultiResolver_Resolve(t *testing.T) {
	addr, stop := startMockDNS(t, map[string][]string{
		"api.example.com": {"1.2.3.4"},
	})
	defer stop()

	res, err := mockMultiResolver(addr).Resolve(context.Background(), "api.example.com")
	require.NoError(t, err)
	assert.Contains(t, res.IPs, "1.2.3.4")
}

func TestMultiResolver_Resolve_CacheHit(t *testing.T) {
	mr := NewMultiResolver(nil)
	mr.cache.Record("cached.example.com", []string{"5.5.5.5"}, 60*time.Second)

	res, err := mr.Resolve(context.Background(), "cached.example.com")
	require.NoError(t, err)
	assert.Contains(t, res.IPs, "5.5.5.5")
}

func TestMultiResolver_Resolve_AllUpstreamsFail_Fallback(t *testing.T) {
	// All upstreams unreachable with a short timeout; falls back to system resolver.
	mr := &MultiResolver{
		upstreams: []string{"127.0.0.1:19753"},
		client:    &mdns.Client{Net: "udp", Timeout: 100 * time.Millisecond},
		cache:     NewIPCache(),
		fallback:  NewActiveResolver(),
	}
	// We only verify the fallback path executes without panic.
	_, _ = mr.Resolve(context.Background(), "one.one.one.one")
}

// ── SnoopResolver ──────────────────────────────────────────────────────────

func TestSnoopResolver_StartAndShutdown(t *testing.T) {
	upstreamAddr, stopUpstream := startMockDNS(t, map[string][]string{})
	defer stopUpstream()

	snoopAddr := freeUDPAddr(t)
	sr := NewSnoopResolver(snoopAddr, upstreamAddr)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	require.NoError(t, sr.Start(ctx))
	sr.Shutdown()
}

func TestSnoopResolver_HandleQuery_RecordsIPs(t *testing.T) {
	upstreamAddr, stopUpstream := startMockDNS(t, map[string][]string{
		"api.example.com": {"1.2.3.4"},
	})
	defer stopUpstream()

	snoopAddr := freeUDPAddr(t)
	sr := NewSnoopResolver(snoopAddr, upstreamAddr)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	require.NoError(t, sr.Start(ctx))
	defer sr.Shutdown()

	c := &mdns.Client{Net: "udp", Timeout: 3 * time.Second}
	msg := new(mdns.Msg)
	msg.SetQuestion(mdns.Fqdn("api.example.com"), mdns.TypeA)
	resp, _, err := c.Exchange(msg, snoopAddr)
	require.NoError(t, err)
	assert.Equal(t, mdns.RcodeSuccess, resp.Rcode)

	assert.Eventually(t, func() bool {
		return len(sr.cache.Get("api.example.com")) > 0
	}, 2*time.Second, 50*time.Millisecond, "snoop proxy should record the resolved IP")
}

func TestSnoopResolver_HandleQuery_NXDOMAIN(t *testing.T) {
	upstreamAddr, stopUpstream := startMockDNS(t, map[string][]string{})
	defer stopUpstream()

	snoopAddr := freeUDPAddr(t)
	sr := NewSnoopResolver(snoopAddr, upstreamAddr)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	require.NoError(t, sr.Start(ctx))
	defer sr.Shutdown()

	c := &mdns.Client{Net: "udp", Timeout: 3 * time.Second}
	msg := new(mdns.Msg)
	msg.SetQuestion(mdns.Fqdn("unknown.example.com"), mdns.TypeA)
	resp, _, err := c.Exchange(msg, snoopAddr)
	require.NoError(t, err)
	assert.Equal(t, mdns.RcodeNameError, resp.Rcode)
}

func TestSnoopResolver_Resolve_UnionsCacheAndMulti(t *testing.T) {
	upstreamAddr, stopUpstream := startMockDNS(t, map[string][]string{
		"api.example.com": {"1.2.3.4"},
	})
	defer stopUpstream()

	// Do not call Start; Resolve works without the proxy running.
	sr := NewSnoopResolver("", upstreamAddr)
	sr.cache.Record("api.example.com", []string{"9.9.9.9"}, 60*time.Second)

	res, err := sr.Resolve(context.Background(), "api.example.com")
	require.NoError(t, err)
	assert.Contains(t, res.IPs, "9.9.9.9")
}

// ── WildcardResolver ───────────────────────────────────────────────────────

func TestWildcardResolver_Resolve_InvalidPattern(t *testing.T) {
	wr := NewWildcardResolver(NewMultiResolver(nil), nil)
	_, err := wr.Resolve(context.Background(), "*.")
	assert.Error(t, err)
}

func TestWildcardResolver_Resolve_PlainFQDN(t *testing.T) {
	addr, stop := startMockDNS(t, map[string][]string{
		"api.example.com": {"1.2.3.4"},
	})
	defer stop()

	wr := NewWildcardResolver(mockMultiResolver(addr), nil)
	res, err := wr.Resolve(context.Background(), "api.example.com")
	require.NoError(t, err)
	assert.Contains(t, res.IPs, "1.2.3.4")
}

func TestWildcardResolver_Resolve_Wildcard(t *testing.T) {
	addr, stop := startMockDNS(t, map[string][]string{
		"api.example.com": {"1.2.3.4"},
		"www.example.com": {"5.6.7.8"},
	})
	defer stop()

	wr := NewWildcardResolver(mockMultiResolver(addr), nil)
	res, err := wr.Resolve(context.Background(), "*.example.com")
	require.NoError(t, err)
	assert.Contains(t, res.IPs, "1.2.3.4")
	assert.Contains(t, res.IPs, "5.6.7.8")
}

func TestWildcardResolver_LearnedPrefixExpanded(t *testing.T) {
	addr, stop := startMockDNS(t, map[string][]string{
		"custom.example.com": {"9.9.9.9"},
	})
	defer stop()

	wr := NewWildcardResolver(mockMultiResolver(addr), nil)
	wr.LearnPrefix("example.com", "custom")

	res, err := wr.Resolve(context.Background(), "*.example.com")
	require.NoError(t, err)
	assert.Contains(t, res.IPs, "9.9.9.9")
}

// ── CNAME chain ────────────────────────────────────────────────────────────

func TestQueryUpstream_CNAMEChain(t *testing.T) {
	// api.example.com → CNAME → foo.cdn.com → CNAME → edge.net → A 1.2.3.4
	mux := mdns.NewServeMux()
	mux.HandleFunc(".", func(w mdns.ResponseWriter, req *mdns.Msg) {
		resp := new(mdns.Msg)
		resp.SetReply(req)
		for _, q := range req.Question {
			if q.Name == "api.example.com." && q.Qtype == mdns.TypeA {
				resp.Answer = []mdns.RR{
					&mdns.CNAME{
						Hdr:    mdns.RR_Header{Name: "api.example.com.", Rrtype: mdns.TypeCNAME, Class: mdns.ClassINET, Ttl: 60},
						Target: "foo.cdn.com.",
					},
					&mdns.CNAME{
						Hdr:    mdns.RR_Header{Name: "foo.cdn.com.", Rrtype: mdns.TypeCNAME, Class: mdns.ClassINET, Ttl: 60},
						Target: "edge.net.",
					},
					&mdns.A{
						Hdr: mdns.RR_Header{Name: "edge.net.", Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 60},
						A:   net.ParseIP("1.2.3.4").To4(),
					},
				}
			}
		}
		_ = w.WriteMsg(resp)
	})

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	srv := &mdns.Server{PacketConn: pc, Net: "udp", Handler: mux}
	ready := make(chan struct{})
	srv.NotifyStartedFunc = func() { close(ready) }
	go func() { _ = srv.ActivateAndServe() }()
	select {
	case <-ready:
	case <-time.After(2 * time.Second):
		t.Fatal("mock DNS server did not start within 2s")
	}
	defer func() { _ = srv.Shutdown() }()

	c := &mdns.Client{Net: "udp", Timeout: 3 * time.Second}
	ips, chain, _, _, err := queryUpstream(c, "api.example.com", pc.LocalAddr().String(), mdns.TypeA)
	require.NoError(t, err)
	assert.Equal(t, []string{"1.2.3.4"}, ips)
	assert.Equal(t, []string{"foo.cdn.com", "edge.net"}, chain)
}
