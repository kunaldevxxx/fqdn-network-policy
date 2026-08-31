package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	netv1alpha1 "github.com/kunaldevxxx/fqdn-network-policy/api/v1alpha1"
	idns "github.com/kunaldevxxx/fqdn-network-policy/internal/dns"
	"github.com/kunaldevxxx/fqdn-network-policy/internal/netpol"

	"github.com/spf13/cobra"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"
)

var (
	coreDNSAddr     string
	noMultiResolver bool
	namespace       string
)

var cgnatNet *net.IPNet

func init() {
	_, cgnatNet, _ = net.ParseCIDR("100.64.0.0/10")
}

func main() {
	root := &cobra.Command{
		Use:   "kubectl-fqdn_policy",
		Short: "Inspect and preview FQDN network policies",
		Long: `kubectl fqdn-policy — preview and diff FQDNNetworkPolicy resources.

Examples:
  kubectl fqdn-policy preview policy.yaml
  kubectl fqdn-policy diff payments/allow-payment-apis
  kubectl fqdn-policy diff allow-payment-apis -n payments`,
	}

	previewCmd := &cobra.Command{
		Use:   "preview <file.yaml>",
		Short: "Resolve FQDNs from a policy file without touching the cluster",
		Args:  cobra.ExactArgs(1),
		RunE:  runPreview,
	}
	previewCmd.Flags().StringVar(&coreDNSAddr, "coredns-address", "", "CoreDNS host:port to query directly")
	previewCmd.Flags().BoolVar(&noMultiResolver, "no-multi-resolver", false, "Use system resolver only instead of 4 public upstreams")

	diffCmd := &cobra.Command{
		Use:   "diff [namespace/]name",
		Short: "Show IP diff between live cluster state and a fresh resolution",
		Args:  cobra.ExactArgs(1),
		RunE:  runDiff,
	}
	diffCmd.Flags().StringVarP(&namespace, "namespace", "n", "", "Namespace of the policy")
	diffCmd.Flags().StringVar(&coreDNSAddr, "coredns-address", "", "CoreDNS host:port to query directly")

	root.AddCommand(previewCmd, diffCmd)
	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

// ── preview ────────────────────────────────────────────────────────────────

func runPreview(cmd *cobra.Command, args []string) error {
	data, err := os.ReadFile(args[0])
	if err != nil {
		return fmt.Errorf("reading %s: %w", args[0], err)
	}

	var meta struct {
		Kind     string `json:"kind"`
		Metadata struct {
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
		} `json:"metadata"`
	}
	if err := yaml.Unmarshal(data, &meta); err != nil {
		return fmt.Errorf("parsing YAML: %w", err)
	}

	var (
		egress          []netv1alpha1.FQDNRule
		security        *netv1alpha1.SecuritySpec
		policyName      string
		policyNS        string
		coreDNSFromSpec string
	)

	switch meta.Kind {
	case "FQDNNetworkPolicy":
		var fp netv1alpha1.FQDNNetworkPolicy
		if err := yaml.Unmarshal(data, &fp); err != nil {
			return fmt.Errorf("unmarshalling FQDNNetworkPolicy: %w", err)
		}
		egress = fp.Spec.Egress
		security = fp.Spec.Security
		policyName = fp.Name
		policyNS = fp.Namespace
		coreDNSFromSpec = fp.Spec.CoreDNSAddress
	case "ClusterFQDNNetworkPolicy":
		var cp netv1alpha1.ClusterFQDNNetworkPolicy
		if err := yaml.Unmarshal(data, &cp); err != nil {
			return fmt.Errorf("unmarshalling ClusterFQDNNetworkPolicy: %w", err)
		}
		egress = cp.Spec.Egress
		security = cp.Spec.Security
		policyName = cp.Name
		policyNS = "(cluster-scoped)"
		coreDNSFromSpec = cp.Spec.CoreDNSAddress
	default:
		return fmt.Errorf("unsupported kind %q — expected FQDNNetworkPolicy or ClusterFQDNNetworkPolicy", meta.Kind)
	}

	resolver := buildResolver(coreDNSFromSpec)

	fmt.Printf("Policy:    %s\n", policyName)
	fmt.Printf("Namespace: %s\n\n", policyNS)

	ctx := context.Background()
	var resolvedHosts []netv1alpha1.ResolvedHost
	var warnings []string

	for _, rule := range egress {
		res, err := resolver.Resolve(ctx, rule.Match)
		if err != nil {
			fmt.Printf("%s\n  ERROR: %v\n\n", rule.Match, err)
			warnings = append(warnings, fmt.Sprintf("[ERR]  %s: %v", rule.Match, err))
			continue
		}

		var v4, v6 []string
		for _, ip := range res.IPs {
			if net.ParseIP(ip).To4() != nil {
				v4 = append(v4, ip)
			} else {
				v6 = append(v6, ip)
			}
		}

		fmt.Printf("%s\n", rule.Match)
		if len(v4) > 0 {
			fmt.Printf("  A:     %s\n", strings.Join(v4, ", "))
		}
		if len(v6) > 0 {
			fmt.Printf("  AAAA:  %s\n", strings.Join(v6, ", "))
		}
		if res.TTL > 0 {
			fmt.Printf("  TTL:   %s\n", res.TTL.Round(time.Second))
		}
		if len(res.CNAMEChain) > 0 {
			fmt.Printf("  CNAME: %s\n", strings.Join(res.CNAMEChain, " → "))
		} else {
			fmt.Printf("  CNAME: (none)\n")
		}

		// Resolver divergence via per-upstream query.
		if mr, ok := resolver.(*idns.MultiResolver); ok {
			upstreamResults := mr.ResolvePerUpstream(ctx, rule.Match)
			uniqueCount := uniqueIPCount(upstreamResults)
			fmt.Printf("  Resolver divergence: %d IPs across %d resolvers\n", uniqueCount, len(upstreamResults))
			if hasDivergence(upstreamResults) {
				warnings = append(warnings, fmt.Sprintf("[WARN] %s: resolver divergence (%d IPs appeared in fewer than all resolvers)", rule.Match, uniqueCount))
			}
			if uniqueCount > 10 {
				warnings = append(warnings, fmt.Sprintf("[WARN] %s: CDN-like IP churn detected (%d distinct IPs observed across resolvers)", rule.Match, uniqueCount))
			}
		}
		fmt.Println()

		// Private IP warnings (before filtering, so the user sees what was blocked).
		for _, ip := range res.IPs {
			if priv, kind := privateIPCategory(ip); priv {
				warnings = append(warnings, fmt.Sprintf("[WARN] %s: %s is a %s address — blocked by security defaults", rule.Match, ip, kind))
			}
		}

		// CNAME depth warning.
		if len(res.CNAMEChain) > 3 {
			warnings = append(warnings, fmt.Sprintf("[WARN] %s: CNAME chain depth %d > 3 — review for potential CNAME hijacking", rule.Match, len(res.CNAMEChain)))
		}

		allowed := applySecurityFilter(res.IPs, security)
		resolvedHosts = append(resolvedHosts, netv1alpha1.ResolvedHost{
			Hostname:   rule.Match,
			IPs:        allowed,
			CNAMEChain: res.CNAMEChain,
			LastSeen:   metav1.Now(),
			Source:     "preview",
		})
	}

	// NetworkPolicy preview.
	synthetic := &netv1alpha1.FQDNNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: policyName, Namespace: "preview"},
		Spec:       netv1alpha1.FQDNNetworkPolicySpec{Egress: egress},
		Status:     netv1alpha1.FQDNNetworkPolicyStatus{ResolvedHosts: resolvedHosts},
	}
	if np, err := netpol.Build(synthetic); err == nil && len(np.Spec.Egress) > 0 {
		fmt.Println("Generated NetworkPolicy would allow:")
		for _, egressRule := range np.Spec.Egress {
			for _, peer := range egressRule.To {
				if peer.IPBlock == nil {
					continue
				}
				if len(egressRule.Ports) == 0 {
					fmt.Printf("  %s (all ports)\n", peer.IPBlock.CIDR)
					continue
				}
				for _, p := range egressRule.Ports {
					fmt.Printf("  %s:%v/%s\n", peer.IPBlock.CIDR, p.Port, *p.Protocol)
				}
			}
		}
		fmt.Println()
	}

	if len(warnings) > 0 {
		fmt.Println("Warnings:")
		for _, w := range warnings {
			fmt.Printf("  %s\n", w)
		}
	}
	return nil
}

// ── diff ───────────────────────────────────────────────────────────────────

func runDiff(cmd *cobra.Command, args []string) error {
	ns := namespace
	name := args[0]
	if parts := strings.SplitN(args[0], "/", 2); len(parts) == 2 {
		ns, name = parts[0], parts[1]
	}
	if ns == "" {
		return fmt.Errorf("namespace required — use -n <namespace> or <namespace>/<name>")
	}

	k8sClient, err := buildK8sClient()
	if err != nil {
		return fmt.Errorf("connecting to cluster: %w", err)
	}

	ctx := context.Background()
	var fp netv1alpha1.FQDNNetworkPolicy
	if err := k8sClient.Get(ctx, types.NamespacedName{Name: name, Namespace: ns}, &fp); err != nil {
		return fmt.Errorf("fetching %s/%s: %w", ns, name, err)
	}

	liveIPs := make(map[string][]string, len(fp.Status.ResolvedHosts))
	for _, host := range fp.Status.ResolvedHosts {
		liveIPs[host.Hostname] = host.IPs
	}

	resolver := buildResolver(fp.Spec.CoreDNSAddress)
	freshIPs := make(map[string][]string, len(fp.Spec.Egress))
	for _, rule := range fp.Spec.Egress {
		res, err := resolver.Resolve(ctx, rule.Match)
		if err != nil {
			fmt.Printf("%s: resolution error: %v\n\n", rule.Match, err)
			continue
		}
		freshIPs[rule.Match] = applySecurityFilter(res.IPs, fp.Spec.Security)
	}

	fmt.Printf("Policy: %s (namespace: %s)\n\n", fp.Name, fp.Namespace)

	anyChange := false
	for _, rule := range fp.Spec.Egress {
		live := toSet(liveIPs[rule.Match])
		fresh := toSet(freshIPs[rule.Match])

		added := setDiff(fresh, live)
		removed := setDiff(live, fresh)

		if len(added) == 0 && len(removed) == 0 {
			continue
		}
		anyChange = true
		fmt.Printf("%s\n", rule.Match)
		for _, ip := range sortedStrs(added) {
			fmt.Printf("  + %s  (new)\n", hostCIDR(ip))
		}
		for _, ip := range sortedStrs(removed) {
			fmt.Printf("  - %s  (stale)\n", hostCIDR(ip))
		}
		fmt.Println()
	}

	if !anyChange {
		fmt.Println("No changes — fresh resolution matches live NetworkPolicy IPs.")
	}
	return nil
}

// ── helpers ────────────────────────────────────────────────────────────────

func buildResolver(specCoreDNS string) idns.Resolver {
	addr := coreDNSAddr
	if addr == "" {
		addr = specCoreDNS
	}
	if noMultiResolver {
		if addr != "" {
			return idns.NewCoreDNSResolver(addr)
		}
		return idns.NewActiveResolver()
	}
	var extra []string
	if addr != "" {
		extra = []string{addr}
	}
	return idns.NewMultiResolver(extra)
}

func buildK8sClient() (client.Client, error) {
	kubeconfig := os.Getenv("KUBECONFIG")
	if kubeconfig == "" {
		if home, err := os.UserHomeDir(); err == nil {
			kubeconfig = filepath.Join(home, ".kube", "config")
		}
	}
	cfg, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return nil, err
	}
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = networkingv1.AddToScheme(scheme)
	_ = netv1alpha1.AddToScheme(scheme)
	return client.New(cfg, client.Options{Scheme: scheme})
}

func uniqueIPCount(results []idns.UpstreamResult) int {
	seen := make(map[string]struct{})
	for _, r := range results {
		for _, ip := range r.IPs {
			seen[ip] = struct{}{}
		}
	}
	return len(seen)
}

func hasDivergence(results []idns.UpstreamResult) bool {
	if len(results) <= 1 {
		return false
	}
	ipCount := make(map[string]int)
	for _, r := range results {
		for _, ip := range r.IPs {
			ipCount[ip]++
		}
	}
	for _, count := range ipCount {
		if count < len(results) {
			return true
		}
	}
	return false
}

// privateIPCategory returns (true, category) when ip is non-public.
func privateIPCategory(ipStr string) (bool, string) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false, ""
	}
	if ip.IsLoopback() {
		return true, "loopback"
	}
	if ip.IsLinkLocalUnicast() {
		return true, "link-local"
	}
	if cgnatNet.Contains(ip) {
		return true, "CGNAT (100.64/10)"
	}
	if ip.IsPrivate() {
		return true, "RFC1918"
	}
	return false, ""
}

// applySecurityFilter mirrors the controller's filterBlockedIPs logic.
func applySecurityFilter(ips []string, sec *netv1alpha1.SecuritySpec) []string {
	blockPrivate := sec == nil || sec.BlockPrivateIPs == nil || *sec.BlockPrivateIPs
	blockLoopback := sec == nil || sec.BlockLoopback == nil || *sec.BlockLoopback
	blockLinkLocal := sec == nil || sec.BlockLinkLocal == nil || *sec.BlockLinkLocal

	var allowed []string
	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			allowed = append(allowed, ipStr)
			continue
		}
		if blockLoopback && ip.IsLoopback() {
			continue
		}
		if blockPrivate && (ip.IsPrivate() || cgnatNet.Contains(ip)) {
			continue
		}
		if blockLinkLocal && ip.IsLinkLocalUnicast() {
			continue
		}
		allowed = append(allowed, ipStr)
	}
	return allowed
}

func toSet(ips []string) map[string]struct{} {
	s := make(map[string]struct{}, len(ips))
	for _, ip := range ips {
		s[ip] = struct{}{}
	}
	return s
}

func setDiff(a, b map[string]struct{}) []string {
	var out []string
	for k := range a {
		if _, ok := b[k]; !ok {
			out = append(out, k)
		}
	}
	return out
}

func sortedStrs(ss []string) []string {
	cp := make([]string, len(ss))
	copy(cp, ss)
	sort.Strings(cp)
	return cp
}

func hostCIDR(ip string) string {
	if net.ParseIP(ip).To4() != nil {
		return ip + "/32"
	}
	return ip + "/128"
}
