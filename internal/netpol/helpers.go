package netpol

import (
	"net"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// hostCIDR returns a host-route CIDR for the given IP string:
// /32 for IPv4, /128 for IPv6. Kubernetes NetworkPolicy requires
// that no bits be set beyond the prefix length, so the mask must
// match the address family.
func hostCIDR(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed != nil && parsed.To4() == nil {
		return ip + "/128"
	}
	return ip + "/32"
}

func corev1Protocol(p string) corev1.Protocol {
	if p == "" {
		return corev1.ProtocolTCP
	}
	return corev1.Protocol(p)
}

func intstrPort(p int32) intstr.IntOrString {
	return intstr.FromInt(int(p))
}
