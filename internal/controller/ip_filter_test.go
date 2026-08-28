package controller

import (
	"testing"

	netv1alpha1 "github.com/kunaldevxxx/fqdn-network-policy/api/v1alpha1"
	"github.com/stretchr/testify/assert"
)

func boolPtr(b bool) *bool { return &b }

// ── default behavior (nil SecuritySpec) ──────────────────────────────────

func TestFilterBlockedIPs_DefaultBlocksRFC1918(t *testing.T) {
	for _, ip := range []string{"10.0.0.1", "172.20.0.1", "192.168.1.1"} {
		allowed, blocked := filterBlockedIPs([]string{ip, "1.2.3.4"}, nil)
		assert.Equal(t, []string{"1.2.3.4"}, allowed, "public IP should pass through alongside %s", ip)
		assert.Len(t, blocked, 1)
		assert.Equal(t, ip, blocked[0].IP)
		assert.Equal(t, "blockPrivateIPs", blocked[0].Field)
	}
}

func TestFilterBlockedIPs_DefaultBlocksCGNAT(t *testing.T) {
	allowed, blocked := filterBlockedIPs([]string{"100.64.0.1"}, nil)
	assert.Empty(t, allowed)
	assert.Len(t, blocked, 1)
	assert.Equal(t, "blockPrivateIPs", blocked[0].Field)
}

func TestFilterBlockedIPs_DefaultBlocksLoopback(t *testing.T) {
	allowed, blocked := filterBlockedIPs([]string{"127.0.0.1"}, nil)
	assert.Empty(t, allowed)
	assert.Equal(t, "blockLoopback", blocked[0].Field)
}

func TestFilterBlockedIPs_DefaultBlocksIPv6Loopback(t *testing.T) {
	allowed, blocked := filterBlockedIPs([]string{"::1"}, nil)
	assert.Empty(t, allowed)
	assert.Equal(t, "blockLoopback", blocked[0].Field)
}

func TestFilterBlockedIPs_DefaultBlocksLinkLocal(t *testing.T) {
	allowed, blocked := filterBlockedIPs([]string{"169.254.1.1"}, nil)
	assert.Empty(t, allowed)
	assert.Equal(t, "blockLinkLocal", blocked[0].Field)
}

func TestFilterBlockedIPs_DefaultBlocksIPv6LinkLocal(t *testing.T) {
	allowed, blocked := filterBlockedIPs([]string{"fe80::1"}, nil)
	assert.Empty(t, allowed)
	assert.Equal(t, "blockLinkLocal", blocked[0].Field)
}

func TestFilterBlockedIPs_PublicIPPassesThrough(t *testing.T) {
	allowed, blocked := filterBlockedIPs([]string{"1.2.3.4", "2001:db8::1"}, nil)
	assert.ElementsMatch(t, []string{"1.2.3.4", "2001:db8::1"}, allowed)
	assert.Empty(t, blocked)
}

func TestFilterBlockedIPs_AllBlocked_EmptyAllowed(t *testing.T) {
	allowed, blocked := filterBlockedIPs([]string{"10.0.0.1", "172.20.0.1", "192.168.1.1"}, nil)
	assert.Empty(t, allowed)
	assert.Len(t, blocked, 3)
}

// ── opt-out via explicit false ────────────────────────────────────────────

func TestFilterBlockedIPs_OptOutPrivate(t *testing.T) {
	sec := &netv1alpha1.SecuritySpec{BlockPrivateIPs: boolPtr(false)}
	allowed, blocked := filterBlockedIPs([]string{"10.0.0.5"}, sec)
	assert.Equal(t, []string{"10.0.0.5"}, allowed)
	assert.Empty(t, blocked)
}

func TestFilterBlockedIPs_OptOutLoopback(t *testing.T) {
	sec := &netv1alpha1.SecuritySpec{BlockLoopback: boolPtr(false)}
	allowed, blocked := filterBlockedIPs([]string{"127.0.0.1"}, sec)
	assert.Equal(t, []string{"127.0.0.1"}, allowed)
	assert.Empty(t, blocked)
}

func TestFilterBlockedIPs_OptOutLinkLocal(t *testing.T) {
	sec := &netv1alpha1.SecuritySpec{BlockLinkLocal: boolPtr(false)}
	allowed, blocked := filterBlockedIPs([]string{"169.254.1.1"}, sec)
	assert.Equal(t, []string{"169.254.1.1"}, allowed)
	assert.Empty(t, blocked)
}

// ── nil field in spec means default (true) ────────────────────────────────

func TestFilterBlockedIPs_NilFieldMeansDefault(t *testing.T) {
	// SecuritySpec set but BlockPrivateIPs not specified: should still block.
	sec := &netv1alpha1.SecuritySpec{MaxCNAMEDepth: nil}
	allowed, blocked := filterBlockedIPs([]string{"10.0.0.1"}, sec)
	assert.Empty(t, allowed)
	assert.Equal(t, "blockPrivateIPs", blocked[0].Field)
}

// ── CIDR accuracy ─────────────────────────────────────────────────────────

func TestFilterBlockedIPs_CIDRReported(t *testing.T) {
	_, blocked := filterBlockedIPs([]string{"10.0.0.5"}, nil)
	assert.Equal(t, "10.0.0.0/8", blocked[0].CIDR)
}

// ── message format ────────────────────────────────────────────────────────

func TestBlockedIP_Message(t *testing.T) {
	b := blockedIP{IP: "10.0.0.5", CIDR: "10.0.0.0/8", Field: "blockPrivateIPs"}
	msg := b.message("api.example.com")
	assert.Contains(t, msg, "api.example.com")
	assert.Contains(t, msg, "10.0.0.5")
	assert.Contains(t, msg, "blockPrivateIPs")
}

// ── DNS rebinding scenario ────────────────────────────────────────────────

func TestFilterBlockedIPs_DNSRebindingScenario(t *testing.T) {
	// Attacker returns a mix: one public IP to seed the policy, then a private
	// one in the next TTL cycle. Only the public IP should survive filtering.
	ips := []string{"203.0.113.1", "10.0.0.5"}
	allowed, blocked := filterBlockedIPs(ips, nil)
	assert.Equal(t, []string{"203.0.113.1"}, allowed)
	assert.Len(t, blocked, 1)
	assert.Equal(t, "10.0.0.5", blocked[0].IP)
}
