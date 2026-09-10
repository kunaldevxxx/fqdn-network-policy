package profiler

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	netv1alpha1 "github.com/kunaldevxxx/fqdn-network-policy/api/v1alpha1"
)

// DomainEvaluation represents the result of simulating policy evaluation for one hostname.
type DomainEvaluation struct {
	Hostname   string    `json:"hostname"`
	QueryCount int64     `json:"queryCount"`
	FirstSeen  time.Time `json:"firstSeen"`
	LastSeen   time.Time `json:"lastSeen"`
	MatchedBy  string    `json:"matchedBy,omitempty"`
	Category   string    `json:"category"`
	Provider   string    `json:"provider"`
}

// SecurityAudit contains warnings and recommendations discovered during simulation.
type SecurityAudit struct {
	Level   string `json:"level"` // "INFO", "WARNING", "CRITICAL"
	Message string `json:"message"`
}

// SimulationReport summarizes the blast radius of applying or enforcing an FQDNNetworkPolicy.
type SimulationReport struct {
	PolicyName      string             `json:"policyName"`
	Namespace       string             `json:"namespace"`
	Mode            string             `json:"mode"`
	TotalObserved   int                `json:"totalObserved"`
	AllowedCount    int                `json:"allowedCount"`
	BlockedCount    int                `json:"blockedCount"`
	InternalCount   int                `json:"internalCount"`
	AllowedDomains  []DomainEvaluation `json:"allowedDomains"`
	BlockedDomains  []DomainEvaluation `json:"blockedDomains"` // The Blast Radius!
	InternalDomains []DomainEvaluation `json:"internalDomains"`
	SecurityAudits  []SecurityAudit    `json:"securityAudits"`
	HasRisk         bool               `json:"hasRisk"`
}

// Simulate evaluates a policy against a list of observed domains and calculates
// the exact blast radius (traffic allowed vs traffic dropped).
func Simulate(policy *netv1alpha1.FQDNNetworkPolicy, observed []netv1alpha1.ObservedDomain) (*SimulationReport, error) {
	if policy == nil {
		return nil, fmt.Errorf("policy is nil")
	}

	report := &SimulationReport{
		PolicyName:    policy.Name,
		Namespace:     policy.Namespace,
		Mode:          string(policy.Spec.Mode),
		TotalObserved: len(observed),
	}
	if report.Mode == "" {
		report.Mode = "Audit"
	}

	for _, obs := range observed {
		class := ClassifyDomain(obs.Hostname)
		eval := DomainEvaluation{
			Hostname:   obs.Hostname,
			QueryCount: obs.QueryCount,
			FirstSeen:  obs.FirstSeen.Time,
			LastSeen:   obs.LastSeen.Time,
			Category:   class.Category,
			Provider:   class.Provider,
		}

		if IsInternalDomain(obs.Hostname) {
			report.InternalDomains = append(report.InternalDomains, eval)
			continue
		}

		matchedRule := findMatchingRule(obs.Hostname, policy.Spec.Egress)
		if matchedRule != "" {
			eval.MatchedBy = matchedRule
			report.AllowedDomains = append(report.AllowedDomains, eval)
		} else {
			report.BlockedDomains = append(report.BlockedDomains, eval)
		}
	}

	report.AllowedCount = len(report.AllowedDomains)
	report.BlockedCount = len(report.BlockedDomains)
	report.InternalCount = len(report.InternalDomains)
	report.HasRisk = report.BlockedCount > 0

	// Security and Completeness Audits
	runSecurityAudits(policy, report)

	return report, nil
}

func findMatchingRule(hostname string, rules []netv1alpha1.FQDNRule) string {
	hostname = strings.ToLower(strings.TrimSpace(hostname))
	hostname = strings.TrimSuffix(hostname, ".")

	for _, rule := range rules {
		match := strings.ToLower(strings.TrimSpace(rule.Match))
		match = strings.TrimSuffix(match, ".")

		if hostname == match {
			return rule.Match
		}

		if suffix, ok := strings.CutPrefix(match, "*."); ok {
			if strings.HasSuffix(hostname, "."+suffix) || hostname == suffix {
				return rule.Match
			}
		}
	}
	return ""
}

func runSecurityAudits(policy *netv1alpha1.FQDNNetworkPolicy, report *SimulationReport) {
	// 1. Check for empty egress rules
	if len(policy.Spec.Egress) == 0 {
		report.SecurityAudits = append(report.SecurityAudits, SecurityAudit{
			Level:   "CRITICAL",
			Message: "Policy specifies no egress rules. If enforced, ALL outbound traffic (except DNS) will be blocked!",
		})
	}

	// 2. Check for overly broad wildcard rules
	for _, rule := range policy.Spec.Egress {
		m := strings.TrimSpace(rule.Match)
		if m == "*" || m == "*.*" {
			report.SecurityAudits = append(report.SecurityAudits, SecurityAudit{
				Level:   "WARNING",
				Message: fmt.Sprintf("Rule %q matches everything, effectively disabling egress filtering.", m),
			})
		}
		if strings.HasPrefix(m, "*.") {
			base := strings.TrimPrefix(m, "*.")
			if !strings.Contains(base, ".") {
				report.SecurityAudits = append(report.SecurityAudits, SecurityAudit{
					Level:   "WARNING",
					Message: fmt.Sprintf("Wildcard rule %q is dangerously broad (covers entire top-level domain).", m),
				})
			}
		}
	}

	// 3. Check private IP blocking
	if policy.Spec.Security == nil || policy.Spec.Security.BlockPrivateIPs == nil || !*policy.Spec.Security.BlockPrivateIPs {
		report.SecurityAudits = append(report.SecurityAudits, SecurityAudit{
			Level:   "WARNING",
			Message: "spec.security.blockPrivateIPs is not enabled; DNS rebinding to internal/link-local IPs (e.g. cloud metadata 169.254.169.254) is possible.",
		})
	} else {
		report.SecurityAudits = append(report.SecurityAudits, SecurityAudit{
			Level:   "INFO",
			Message: "DNS safety guard active: private/loopback/link-local IPs will be blocked.",
		})
	}

	// 4. Mode awareness
	if policy.Spec.Mode == netv1alpha1.PolicyModeAudit {
		report.SecurityAudits = append(report.SecurityAudits, SecurityAudit{
			Level:   "INFO",
			Message: "Policy is in Audit mode: no traffic will be dropped upon application.",
		})
	} else if report.BlockedCount > 0 {
		report.SecurityAudits = append(report.SecurityAudits, SecurityAudit{
			Level:   "CRITICAL",
			Message: fmt.Sprintf("Policy is in Enforce mode and %d observed domains will be immediately BLOCKED!", report.BlockedCount),
		})
	}
}

// JSON exports the simulation report as formatted JSON.
func (r *SimulationReport) JSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

// String renders a clear, human-readable terminal report.
func (r *SimulationReport) String() string {
	var b strings.Builder

	banner := "================================================================================"
	b.WriteString(banner + "\n")
	b.WriteString(fmt.Sprintf(" BLAST RADIUS REPORT: %s/%s (Mode: %s)\n", r.Namespace, r.PolicyName, r.Mode))
	b.WriteString(banner + "\n\n")

	if r.HasRisk {
		b.WriteString(fmt.Sprintf("⚠️  RISK DETECTED: %d actively observed domain(s) would be BLOCKED!\n\n", r.BlockedCount))
	} else {
		b.WriteString("✓ SAFE: All observed external domains are permitted by the proposed policy.\n\n")
	}

	b.WriteString(fmt.Sprintf("Coverage Breakdown:\n"))
	b.WriteString(fmt.Sprintf("  Total Domains Observed:  %d\n", r.TotalObserved))
	b.WriteString(fmt.Sprintf("  Allowed by Policy:       %d\n", r.AllowedCount))
	b.WriteString(fmt.Sprintf("  BLOCKED (Blast Radius):  %d\n", r.BlockedCount))
	b.WriteString(fmt.Sprintf("  Internal K8s (Ignored):  %d\n\n", r.InternalCount))

	if len(r.BlockedDomains) > 0 {
		b.WriteString("--------------------------------------------------------------------------------\n")
		b.WriteString(" [BLAST RADIUS] DOMAINS THAT WOULD BE BLOCKED:\n")
		b.WriteString("--------------------------------------------------------------------------------\n")
		for _, d := range r.BlockedDomains {
			queries := ""
			if d.QueryCount > 0 {
				queries = fmt.Sprintf(" (queries: %d)", d.QueryCount)
			}
			b.WriteString(fmt.Sprintf("  ✗ %-32s [%s / %s]%s\n", d.Hostname, d.Category, d.Provider, queries))
		}
		b.WriteString("\n")
	}

	if len(r.AllowedDomains) > 0 {
		b.WriteString("--------------------------------------------------------------------------------\n")
		b.WriteString(" [ALLOWED] DOMAINS PERMITTED BY POLICY:\n")
		b.WriteString("--------------------------------------------------------------------------------\n")
		// Show up to 10 allowed domains
		limit := len(r.AllowedDomains)
		if limit > 10 {
			limit = 10
		}
		for i := 0; i < limit; i++ {
			d := r.AllowedDomains[i]
			b.WriteString(fmt.Sprintf("  ✓ %-32s (matched by: %s)\n", d.Hostname, d.MatchedBy))
		}
		if len(r.AllowedDomains) > 10 {
			b.WriteString(fmt.Sprintf("  ... and %d more allowed domains\n", len(r.AllowedDomains)-10))
		}
		b.WriteString("\n")
	}

	if len(r.SecurityAudits) > 0 {
		b.WriteString("--------------------------------------------------------------------------------\n")
		b.WriteString(" SECURITY & SANITY AUDIT:\n")
		b.WriteString("--------------------------------------------------------------------------------\n")
		for _, audit := range r.SecurityAudits {
			symbol := "ℹ"
			if audit.Level == "WARNING" {
				symbol = "!"
			} else if audit.Level == "CRITICAL" {
				symbol = "✗"
			}
			b.WriteString(fmt.Sprintf("  [%s] %s %s\n", audit.Level, symbol, audit.Message))
		}
		b.WriteString("\n")
	}

	b.WriteString(banner + "\n")
	return b.String()
}
