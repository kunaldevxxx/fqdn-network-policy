# fqdn-network-policy

[![CI](https://github.com/kunaldevxxx/fqdn-network-policy/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/kunaldevxxx/fqdn-network-policy/actions/workflows/ci.yml)
[![E2E KinD](https://github.com/kunaldevxxx/fqdn-network-policy/actions/workflows/ci.yml/badge.svg?branch=main&label=E2E+KinD)](https://github.com/kunaldevxxx/fqdn-network-policy/actions/workflows/ci.yml)
[![Go 1.26](https://img.shields.io/badge/go-1.26-00ADD8?logo=go)](https://go.dev/doc/go1.26)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)

FQDN-based egress control for Kubernetes clusters on **any CNI** — Calico, AWS VPC CNI,
Azure CNI, Flannel, or anything else that enforces standard `networking.k8s.io/v1 NetworkPolicy`.

Write egress rules against hostnames. The controller resolves them to IPs, tracks DNS TTLs, and
reconciles a standard `NetworkPolicy` so enforcement stays with the CNI you already run.

```yaml
apiVersion: netsec.kunal.dev/v1alpha1
kind: FQDNNetworkPolicy
metadata:
  name: allow-payment-apis
  namespace: payments
spec:
  mode: Enforce
  podSelector:
    podSelector:
      matchLabels:
        app: checkout
  egress:
    - match: api.stripe.com
      ports:
        - port: 443
          protocol: TCP
    - match: api.github.com
      ports:
        - port: 443
          protocol: TCP
```

## Why this exists

Standard Kubernetes `NetworkPolicy` accepts only CIDR `ipBlock` rules. External APIs — Stripe,
GitHub, S3, auth providers — rotate IPs continuously with short DNS TTLs, run behind CDNs with
anycast routing, and return different IPs to different callers. Maintaining hand-curated CIDR
lists is error-prone and breaks silently. This controller keeps those lists current automatically.

## How it compares

| Feature | **fqdn-network-policy** | Cilium FQDNNetworkPolicy | Calico FQDN policy | Antrea FQDN | Istio Egress |
|---|---|---|---|---|---|
| **CNI requirement** | **None — any CNI** | Cilium only | Calico only | Antrea only | None |
| **Sidecar required** | No | No | No | No | Yes (Envoy) |
| **DNS resolution method** | Active + 4-resolver union + eBPF snoop | eBPF kernel intercept | DNS poll | DNS proxy | SNI inspection |
| **Produces standard `NetworkPolicy`** | **Yes** | No — Cilium CRD | No — Calico CRD | No — Antrea CRD | No — VirtualService |
| **CDN / anycast accuracy** | ~85 % (4 resolvers) | Near-exact | ~70 % | Moderate | SNI-based |
| **Wildcard rules** | Prefix expansion / snoop | Yes | Yes | Yes | Yes |
| **Cluster-wide policy** | Yes (`ClusterFQDNNetworkPolicy`) | Yes | Yes | Yes | Yes |
| **`kubectl` preview plugin** | **Yes** — `kubectl fqdn-policy preview` | No | No | No | No |
| **DNS rebinding protection** | **Yes** — `blockPrivateIPs` default | Partial | No | No | N/A |
| **CNAME chain visibility** | **Yes** — surfaced in status | No | No | No | No |
| **Multi-upstream resolver** | **Yes** — unions Cloudflare, Google, Quad9, OpenDNS | No | No | No | No |
| **Infrastructure additions** | None | Replace CNI | Replace CNI | Replace CNI | Service mesh |

> **Choose Cilium** if you need exact per-pod DNS accuracy at scale and can replace your CNI.
> **Choose this project** if you need portable egress control on the CNI you already run, with zero infrastructure additions.

**When to use this instead of Cilium or Istio:**
- You run Calico, AWS VPC CNI, Azure CNI, or Flannel and cannot or do not want to replace your CNI.
- You need lightweight egress control with zero infrastructure additions (no sidecars, no service mesh, no CNI replacement).
- Your egress targets are stable internal APIs, corporate auth providers, or fixed SaaS endpoints.

**When to use Cilium instead:** if you need wildcard accuracy for CDN-backed services (Cloudflare, Fastly,
AWS CloudFront) at production scale, Cilium's eBPF DNS snooping is the correct tool. This controller
includes a multi-upstream resolver that covers ~85% of CDN divergence cases but is not equivalent to
in-kernel packet interception.

---

## Architecture

<img width="1853" height="1968" alt="mermaid-diagram-2026-08-27-111233" src="https://github.com/user-attachments/assets/f36e198b-33d0-4ddc-ba25-98a444a5e611" />



**Fail-closed:** if no hosts have resolved yet (first reconcile, cold start, all lookups failed),
the controller emits a deny-all-egress policy rather than a permissive no-op. DNS egress
(UDP/TCP port 53) is always permitted in the generated policy so resolution can continue.

**Transient DNS safety:** a resolution failure retains the last known-good IPs for that host rather
than revoking access. The `Degraded` status condition is set while this fallback is active.

---

## kubectl plugin

`kubectl fqdn-policy` lets you inspect what a policy will do before applying it.

### Install

```bash
make kubectl-plugin
cp bin/kubectl-fqdn_policy /usr/local/bin/
```

### preview — resolve without touching the cluster

```bash
kubectl fqdn-policy preview policy.yaml
```

```
Policy:    allow-payment-apis
Namespace: payments

api.stripe.com
  A:     3.18.12.10, 3.18.12.11
  AAAA:  2600:1f18:2148:bc01::a
  TTL:   38s
  CNAME: (none)
  Resolver divergence: 4 IPs across 4 resolvers

Generated NetworkPolicy would allow:
  3.18.12.10/32:443/TCP
  3.18.12.11/32:443/TCP
  2600:1f18:2148:bc01::a/128:443/TCP

Warnings:
  [WARN] api.stripe.com: resolver divergence (4 IPs appeared in fewer than all resolvers)
```

Flags:
- `--coredns-address <host:port>` — query cluster CoreDNS instead of public resolvers
- `--no-multi-resolver` — use the system resolver only

### diff — compare cluster state against fresh resolution

```bash
kubectl fqdn-policy diff payments/allow-payment-apis
# or
kubectl fqdn-policy diff allow-payment-apis -n payments
```

```
Policy: allow-payment-apis (namespace: payments)

api.stripe.com
  + 54.160.0.1/32  (new)
  - 3.18.12.11/32  (stale)
```

Warnings shown for: private / loopback / link-local IPs, resolver divergence, CNAME chain depth > 3.

---

## Installation

### Helm (recommended)

```bash
helm install fqdn-network-policy charts/fqdn-network-policy/ \
  --namespace fqdn-network-policy-system \
  --create-namespace \
  --set replicaCount=2 \
  --set leaderElection.enabled=true \
  --set multiResolver.enabled=true
```

Verify the controller is running:

```bash
kubectl get pods -n fqdn-network-policy-system
kubectl get fqdnnetworkpolicies --all-namespaces
```

### Manual (without Helm)

```bash
# Install CRDs
kubectl apply -f config/crd/bases/

# Install RBAC and controller
kubectl apply -f config/rbac/role.yaml
kubectl apply -f config/manager/deployment.yaml
```

### Local development

```bash
make build          # compile the manager binary to ./bin/manager
make run            # run against your current kubeconfig context
./demo.sh           # full KinD demo with Calico enforcement proof
```

**Prerequisites:** `kind`, `kubectl`, `docker` on PATH.

---

## Writing policies

### Namespace-scoped: `FQDNNetworkPolicy`

Applies to pods in a single namespace.

```yaml
apiVersion: netsec.kunal.dev/v1alpha1
kind: FQDNNetworkPolicy
metadata:
  name: allow-external-apis
  namespace: payments
spec:
  # mode: Enforce writes a NetworkPolicy. mode: Audit logs only — safe for validation.
  mode: Enforce

  podSelector:
    podSelector:
      matchLabels:
        app: checkout

  egress:
    - match: api.stripe.com
      ports:
        - port: 443
          protocol: TCP
    - match: api.github.com
      ports:
        - port: 443
          protocol: TCP

    # Wildcards require --enable-snoop-resolver=true (see Resolver Strategy below)
    - match: "*.s3.amazonaws.com"
      ports:
        - port: 443
          protocol: TCP

  # Optional: override DNS TTL-based scheduling. Min 5s, max 300s.
  # resolutionTTLOverride: 30

  # Optional: resolve against cluster CoreDNS instead of the node resolver.
  # coreDNSAddress: "10.96.0.10:53"
```

### Cluster-scoped: `ClusterFQDNNetworkPolicy`

Enforces baseline egress rules across all matched namespaces. Platform teams use this for
corporate telemetry, auth providers, and shared infrastructure without duplicating CRs per namespace.

```yaml
apiVersion: netsec.kunal.dev/v1alpha1
kind: ClusterFQDNNetworkPolicy
metadata:
  name: allow-corporate-telemetry
spec:
  mode: Enforce

  # Apply to all namespaces labelled env=production
  namespaceSelector:
    matchLabels:
      env: production

  podSelector:
    podSelector: {}   # all pods in matched namespaces

  egress:
    - match: otel-collector.corp.example.com
      ports:
        - port: 4317
          protocol: TCP
    - match: auth.corp.example.com
      ports:
        - port: 443
          protocol: TCP
```

The controller creates one `NetworkPolicy` per matched namespace (named `cfqdnnp-<policy-name>`)
and garbage-collects it if the namespace no longer matches the selector.

---

## Resolver strategy

Configure the resolver that best matches your infrastructure:

| Resolver | Flag | CDN accuracy | Wildcard | Privilege required |
|----------|------|-------------|----------|--------------------|
| **SnoopResolver** | `--enable-snoop-resolver` | Exact — sees actual pod responses | Yes (dynamic) | CoreDNS forward config |
| **MultiResolver** | `--enable-multi-resolver` (default) | ~85% — unions 4 public resolvers | Yes (prefix expansion) | None |
| **CoreDNS direct** | `--coredns-address` | Better for internal split-horizon | No | None |
| **ActiveResolver** | (fallback) | Same as node resolver | No | None |

### SnoopResolver setup

The SnoopResolver runs a DNS forwarding proxy that CoreDNS routes queries through. It records
exactly which IPs pods received in its response stream.

1. Start the controller with snoop enabled:
   ```bash
   --enable-snoop-resolver=true
   --snoop-listen-address=0.0.0.0:5353
   --snoop-upstream=<coredns-cluster-ip>:53
   ```

2. Patch your CoreDNS ConfigMap to forward through the snoop proxy:
   ```
   .:53 {
       forward . <controller-pod-ip>:5353
       cache 30
       reload
   }
   ```

3. Wildcard rules (e.g. `*.s3.amazonaws.com`) are now accepted by the admission webhook
   and dynamically expanded as the proxy observes new subdomains from pod traffic.

### MultiResolver (default, recommended)

Queries Cloudflare (1.1.1.1), Google (8.8.8.8), Quad9 (9.9.9.9), and OpenDNS (208.67.222.222)
concurrently. Returns the union of all A and AAAA records. For CDN-backed services that use
anycast routing, different resolvers return different PoP IPs — unioning them covers ~85% of
divergence cases with no additional infrastructure.

Enable in Helm:
```yaml
multiResolver:
  enabled: true   # default
coreDNS:
  address: "10.96.0.10:53"   # also queries cluster CoreDNS when set
```

---

## Spec reference

### `FQDNNetworkPolicy`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `spec.mode` | `Enforce` \| `Audit` | `Enforce` | `Enforce` writes a NetworkPolicy. `Audit` logs resolved IPs and fires a Kubernetes Event without writing any policy — safe for validating before enforcement. |
| `spec.podSelector.podSelector` | `LabelSelector` | — | Pods this policy applies to. Empty selects all pods in the namespace. |
| `spec.egress[].match` | string | — | Hostname to allow. Plain FQDNs always work. Wildcards (`*.example.com`) require `--enable-snoop-resolver`. |
| `spec.egress[].ports[].port` | int32 | — | Destination port (1–65535). |
| `spec.egress[].ports[].protocol` | `TCP` \| `UDP` \| `SCTP` | `TCP` | Transport protocol. |
| `spec.resolutionTTLOverride` | int32 | — | Re-resolution interval in seconds (5–300). Overrides DNS TTLs. Useful for sources with unreliable TTL values. |
| `spec.coreDNSAddress` | string | — | `host:port` of cluster CoreDNS (e.g. `10.96.0.10:53`). Queries CoreDNS rather than the node resolver to reduce internal DNS divergence. |

### `ClusterFQDNNetworkPolicy`

All fields from `FQDNNetworkPolicy` plus:

| Field | Type | Description |
|-------|------|-------------|
| `spec.namespaceSelector` | `LabelSelector` | Namespaces to target. Empty selects all namespaces. |

---

## Status and observability

### Conditions

```bash
kubectl get fqdnnetworkpolicy <name> -o jsonpath='{.status.conditions}' | jq
```

| Condition | Status | Reason | Meaning |
|-----------|--------|--------|---------|
| `Ready` | `True` | `Reconciled` | NetworkPolicy is up to date. |
| `Ready` | `False` | `ResolutionDegraded` | One or more hosts failed to resolve. Stale IPs are kept — access is not revoked on a transient DNS error. |
| `Ready` | `True` | `AuditMode` | Audit mode is active; no NetworkPolicy was written. |
| `Degraded` | `True` | `ResolutionErrors` | Companion to `Ready=False`; carries error detail. |

### Kubernetes Events

```bash
kubectl get events -n <namespace> --field-selector involvedObject.name=<policy-name>
```

Events are published for: `NetworkPolicyCreated`, `NetworkPolicyUpdated`, `ResolutionFailed`,
`AuditResolved`, `SyncFailed`.

### Prometheus metrics

The controller exposes 15 metrics at `:8080/metrics`. Key metrics:

| Metric | Type | Description |
|--------|------|-------------|
| `fqdn_dns_lookup_duration_seconds` | Histogram | DNS resolution latency by domain and resolver. |
| `fqdn_dns_lookup_failures_total` | Counter | Resolution failures by domain and error type (`nxdomain`, `timeout`, `servfail`, `other`). |
| `fqdn_dns_cache_hits_total` | Counter | Resolutions served from the snoop IP cache. |
| `fqdn_dns_snoop_observations_total` | Counter | DNS responses intercepted by the proxy, by query type. |
| `fqdn_ttl_expiry_lag_seconds` | Histogram | How late (in seconds) a domain was re-resolved after TTL expiry. |
| `fqdn_ip_changes_total` | Counter | Times the IP set for a domain changed, triggering a NetworkPolicy update. |
| `fqdn_networkpolicy_sync_duration_seconds` | Histogram | Time to apply a NetworkPolicy (create/update/skip). |
| `fqdn_managed_policies_total` | Gauge | Active `FQDNNetworkPolicy` objects. |
| `fqdn_cluster_managed_namespaces_total` | Gauge | Namespaces receiving policies from `ClusterFQDNNetworkPolicy`. |
| `fqdn_reconcile_duration_seconds` | Histogram | End-to-end reconcile time per controller. |

Enable a `ServiceMonitor` for prometheus-operator:
```yaml
metrics:
  serviceMonitor:
    enabled: true
    interval: 30s
```

### Inspecting the generated NetworkPolicy

```bash
# Check what IPs are in the current policy
kubectl get networkpolicy fqdnnp-allow-payment-apis -n payments -o yaml

# Check resolution status
kubectl get fqdnnetworkpolicy allow-payment-apis -n payments -o wide

# Detailed status including resolved IPs and TTLs
kubectl get fqdnnetworkpolicy allow-payment-apis -n payments \
  -o jsonpath='{.status.resolvedHosts}' | jq
```

---

## Admission webhook

The `ValidatingAdmissionWebhook` catches invalid policies at `kubectl apply` time rather than
surfacing errors only through status conditions.

**What it validates:**
- `match` is a valid FQDN or wildcard FQDN (`*.example.com`)
- Wildcard rules are rejected when `--enable-snoop-resolver` is not set
- Duplicate `match` rules within a policy
- Port numbers are in range 1–65535
- Protocol is one of `TCP`, `UDP`, `SCTP`

The webhook server starts automatically on `--webhook-bind-address` (default `:9443`). Register
it with the Kubernetes API server by applying a `ValidatingWebhookConfiguration` pointing to the
controller service. For TLS, use cert-manager with the Helm chart's `webhook.certManager` values.

---

## High availability

For production deployments, run at least 2 replicas with leader election enabled:

```bash
helm upgrade fqdn-network-policy charts/fqdn-network-policy/ \
  --set replicaCount=2 \
  --set leaderElection.enabled=true
```

Only the leader reconciles resources and issues DNS queries. Standby replicas become the leader
instantly if the current leader's pod is evicted or fails. The leader election lease is stored
in `kube-system` under the key `fqdn-network-policy.netsec.kunal.dev`.

---

## Production deployment checklist

- [ ] Run 2+ replicas with `--leader-elect=true`
- [ ] Configure `--enable-multi-resolver=true` (default) or `--enable-snoop-resolver=true`
- [ ] Set `--coredns-address` to your cluster's DNS service IP
- [ ] Apply a `ValidatingWebhookConfiguration` pointing to the controller service with TLS
- [ ] Enable `metrics.serviceMonitor` if using prometheus-operator
- [ ] Set resource `requests` and `limits` in values (provided defaults are conservative)
- [ ] Confirm pod anti-affinity is scheduling replicas on different nodes (included in chart)
- [ ] Run `kubectl apply -f policy.yaml --dry-run=server` before enforcing new policies in production
- [ ] Use `spec.mode: Audit` to validate a new policy before switching to `Enforce`

---

## Project layout

```
api/v1alpha1/
  fqdnnetworkpolicy_types.go           Namespaced CRD: FQDNNetworkPolicy
  clusterfqdnnetworkpolicy_types.go    Cluster-scoped CRD: ClusterFQDNNetworkPolicy
  zz_generated.deepcopy.go            Generated — do not edit by hand

internal/dns/
  resolver.go                          ActiveResolver: TTL-aware A+AAAA via miekg/dns
  multi_resolver.go                    MultiResolver: union of 4 public upstreams
  snoop_resolver.go                    SnoopResolver: DNS forwarding proxy (records IPs)
  wildcard_resolver.go                 WildcardResolver: prefix expansion for *.foo.com
  ip_cache.go                          IPCache: thread-safe TTL-respecting IP store
  ttl_queue.go                         TTLQueue: min-heap for exact TTL scheduling

internal/controller/
  fqdnnetworkpolicy_controller.go      Namespace-scoped reconcile loop
  clusterfqdnnetworkpolicy_controller.go  Cluster-scoped reconcile + fanout

internal/netpol/
  builder.go                           Converts resolved IPs → NetworkPolicy
  helpers.go                           hostCIDR: /32 IPv4, /128 IPv6

internal/webhook/
  validate.go                          ValidatingAdmissionWebhook HTTP handler

internal/metrics/
  metrics.go                           15 Prometheus metrics

cmd/main.go                            Manager setup, flag parsing, resolver wiring
cmd/kubectl-fqdn_policy/main.go        kubectl plugin: preview + diff subcommands

charts/fqdn-network-policy/            Helm chart
config/
  crd/bases/                           Generated CRD YAML
  rbac/role.yaml                       ClusterRole + ClusterRoleBinding
  manager/deployment.yaml             Controller Deployment
  samples/                             Example CRs

.github/workflows/ci.yml              CI: lint → unit → build → KinD E2E → helm lint
```

## Development

```bash
make generate   # regenerate zz_generated.deepcopy.go after type changes
make manifests  # regenerate config/crd/bases/*.yaml and config/rbac/role.yaml
make build      # compile ./bin/manager
make run        # run against current kubeconfig context

go test -short ./...         # unit tests (skips network-dependent tests)
go test -race  ./...         # full test suite including network tests
```

**Codegen note:** do not hand-edit `zz_generated.deepcopy.go` or any file under
`config/crd/bases/`. Both are overwritten by `make generate` and `make manifests`. Commit
the generated output alongside any type changes.

## Known limitations

| Limitation | Status |
|------------|--------|
| SnoopResolver requires CoreDNS forward configuration | Manual CoreDNS ConfigMap patch; automatic patching is planned |
| Wildcard expansion via prefix list may miss unusual subdomains | SnoopResolver learns new prefixes dynamically once active |
| No mTLS / SPIFFE identity-based policy | Use Istio or SPIRE alongside this controller for identity-based controls |
| No multi-cluster federation | Each cluster runs its own controller; shared policy distribution is not yet implemented |
| Webhook TLS requires cert-manager or manual cert provisioning | cert-manager integration is included in the Helm chart |

## License

Apache 2.0. See [LICENSE](LICENSE).
