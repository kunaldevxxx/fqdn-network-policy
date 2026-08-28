package controller

import (
	"fmt"
	"net"

	netv1alpha1 "github.com/kunaldevxxx/fqdn-network-policy/api/v1alpha1"
)

// blockedIP describes a single address that was dropped by the security policy.
type blockedIP struct {
	IP    string
	CIDR  string
	Field string // "blockPrivateIPs" | "blockLoopback" | "blockLinkLocal"
}

func (b blockedIP) message(hostname string) string {
	return fmt.Sprintf("%s resolved to private IP %s (blocked by security.%s)", hostname, b.IP, b.Field)
}

var (
	// privateNets covers RFC1918 and CGNAT (100.64.0.0/10).
	privateNets = mustParseCIDRs(
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"100.64.0.0/10",
	)

	loopbackNets = mustParseCIDRs(
		"127.0.0.0/8",
		"::1/128",
	)

	linkLocalNets = mustParseCIDRs(
		"169.254.0.0/16",
		"fe80::/10",
	)
)

func mustParseCIDRs(cidrs ...string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			panic("ip_filter: bad CIDR " + c + ": " + err.Error())
		}
		out = append(out, n)
	}
	return out
}

func matchingCIDR(ip net.IP, nets []*net.IPNet) *net.IPNet {
	for _, n := range nets {
		if n.Contains(ip) {
			return n
		}
	}
	return nil
}

// filterBlockedIPs splits ips into allowed and blocked based on the security
// spec. When sec is nil every block category is active (fail-safe default).
// An explicit *bool false in the spec opts out of that specific check.
func filterBlockedIPs(ips []string, sec *netv1alpha1.SecuritySpec) (allowed []string, blocked []blockedIP) {
	doBlock := func(field func(*netv1alpha1.SecuritySpec) *bool) bool {
		if sec == nil {
			return true // default: block
		}
		f := field(sec)
		return f == nil || *f // nil → default true; explicit false opts out
	}

	blockPrivate := doBlock(func(s *netv1alpha1.SecuritySpec) *bool { return s.BlockPrivateIPs })
	blockLoopback := doBlock(func(s *netv1alpha1.SecuritySpec) *bool { return s.BlockLoopback })
	blockLinkLocal := doBlock(func(s *netv1alpha1.SecuritySpec) *bool { return s.BlockLinkLocal })

	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			// Unparseable address: pass through so the caller can see it.
			allowed = append(allowed, ipStr)
			continue
		}
		if blockLoopback {
			if n := matchingCIDR(ip, loopbackNets); n != nil {
				blocked = append(blocked, blockedIP{IP: ipStr, CIDR: n.String(), Field: "blockLoopback"})
				continue
			}
		}
		if blockPrivate {
			if n := matchingCIDR(ip, privateNets); n != nil {
				blocked = append(blocked, blockedIP{IP: ipStr, CIDR: n.String(), Field: "blockPrivateIPs"})
				continue
			}
		}
		if blockLinkLocal {
			if n := matchingCIDR(ip, linkLocalNets); n != nil {
				blocked = append(blocked, blockedIP{IP: ipStr, CIDR: n.String(), Field: "blockLinkLocal"})
				continue
			}
		}
		allowed = append(allowed, ipStr)
	}
	return
}
