package dns

import (
	"context"
	"fmt"
	"strings"
	"sync"
)

// commonPrefixes is a broad list of subdomain prefixes found on most
// enterprise SaaS and cloud APIs. For *.foo.com rules we expand them all,
// resolve each, and union the results. This is not perfect — it over-queries
// and misses unusual subdomains — but it covers the vast majority of
// real-world CDN and multi-region API patterns without eBPF.
var commonPrefixes = []string{
	"api", "www", "cdn", "assets", "static", "media", "app", "auth",
	"login", "account", "accounts", "admin", "dashboard", "portal",
	"ws", "socket", "wss", "upload", "download", "images", "img",
	"data", "stream", "live", "edge", "gateway", "proxy",
	"webhooks", "hooks", "events", "notify", "push", "feed",
	"search", "analytics", "telemetry", "metrics", "ops",
	"ingest", "collector", "sink", "export",
	"us", "eu", "ap", "us-east", "us-west", "eu-west", "ap-east",
	"us-east-1", "us-west-2", "eu-central-1",
	"prod", "production", "staging", "sandbox",
	"s3", "storage", "blob", "files", "content",
	"mail", "smtp", "imap", "mx",
	"customer", "customers", "partner", "partners",
	"developer", "dev", "developers", "docs",
}

// WildcardResolver expands *.foo.com patterns by probing common subdomain
// prefixes via the underlying MultiResolver, then taking the union of all
// resolved IPs. It also maintains a learned prefix set — whenever the
// SnoopResolver cache records a new subdomain of a wildcard domain, it is
// added for future expansions.
type WildcardResolver struct {
	base     *MultiResolver
	cache    *IPCache
	learnedMu sync.RWMutex
	learned  map[string][]string // baseDomain → extra prefixes observed via snoop
}

// NewWildcardResolver creates a WildcardResolver backed by the given MultiResolver.
// Pass the SnoopResolver's IPCache to enable dynamic prefix learning.
func NewWildcardResolver(base *MultiResolver, snoopCache *IPCache) *WildcardResolver {
	if snoopCache == nil {
		snoopCache = NewIPCache()
	}
	return &WildcardResolver{
		base:    base,
		cache:   snoopCache,
		learned: make(map[string][]string),
	}
}

// Resolve handles both plain FQDNs and wildcard patterns (*.foo.com).
// For plain FQDNs it delegates to the underlying MultiResolver.
// For wildcards it expands all known prefixes concurrently.
func (w *WildcardResolver) Resolve(ctx context.Context, hostname string) (Resolution, error) {
	if !strings.HasPrefix(hostname, "*.") {
		return w.base.Resolve(ctx, hostname)
	}

	baseDomain := strings.TrimPrefix(hostname, "*.")
	if baseDomain == "" {
		return Resolution{}, fmt.Errorf("invalid wildcard pattern: %q", hostname)
	}

	prefixes := w.allPrefixes(baseDomain)
	type result struct {
		res Resolution
		err error
	}
	ch := make(chan result, len(prefixes))
	sem := make(chan struct{}, 20) // bound concurrency

	for _, prefix := range prefixes {
		fqdn := prefix + "." + baseDomain
		go func(h string) {
			sem <- struct{}{}
			defer func() { <-sem }()
			res, err := w.base.Resolve(ctx, h)
			ch <- result{res: res, err: err}
		}(fqdn)
	}

	ipSet := make(map[string]struct{})
	minTTL := ttlCeiling
	for range prefixes {
		r := <-ch
		if r.err != nil {
			continue
		}
		for _, ip := range r.res.IPs {
			ipSet[ip] = struct{}{}
		}
		if r.res.TTL > 0 && r.res.TTL < minTTL {
			minTTL = r.res.TTL
		}
	}

	if len(ipSet) == 0 {
		return Resolution{}, fmt.Errorf("wildcard expansion for %s produced no IPs across %d prefixes", hostname, len(prefixes))
	}

	ips := make([]string, 0, len(ipSet))
	for ip := range ipSet {
		ips = append(ips, ip)
	}

	return Resolution{
		Hostname: hostname,
		IPs:      ips,
		TTL:      clampTTL(minTTL),
	}, nil
}

// LearnPrefix records a new subdomain prefix for a wildcard base domain,
// discovered by the SnoopResolver observing live pod traffic. Future
// wildcard expansions for that domain will include this prefix.
func (w *WildcardResolver) LearnPrefix(baseDomain, prefix string) {
	w.learnedMu.Lock()
	defer w.learnedMu.Unlock()
	existing := w.learned[baseDomain]
	for _, p := range existing {
		if p == prefix {
			return
		}
	}
	w.learned[baseDomain] = append(existing, prefix)
}

func (w *WildcardResolver) allPrefixes(baseDomain string) []string {
	w.learnedMu.RLock()
	extra := append([]string{}, w.learned[baseDomain]...)
	w.learnedMu.RUnlock()
	return uniqueStrings(append(commonPrefixes, extra...))
}
