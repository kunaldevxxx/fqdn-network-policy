# fqdn-network-policy

CNI-agnostic FQDN-based egress control for Kubernetes. Write rules against
hostnames instead of IP addresses; the controller resolves them and reconciles
a standard `networking.k8s.io/v1 NetworkPolicy`, so enforcement is handled by
whatever CNI the cluster already runs — Calico, AWS VPC CNI, Azure CNI, and
anything else that honors the standard.

**Why this exists:** Kubernetes NetworkPolicy only accepts CIDRs in `ipBlock`
rules. External services (Stripe, GitHub, S3) rotate IPs constantly, so
maintaining hand-curated CIDR lists is error-prone and breaks silently. This
controller keeps those lists current automatically.

## How it works

```
FQDNNetworkPolicy (your CR)
        │
        │  reconcile loop
        ▼
  dns.Resolver ──────► resolves each FQDN to current IPs
        │
        ▼
  netpol.Build ──────► constructs a NetworkPolicy with ipBlock CIDRs
        │                (IPv4 → /32, IPv6 → /128)
        ▼
  NetworkPolicy ─────► Calico / AWS VPC CNI / Azure CNI enforces it
```

The controller re-queues after each policy's `resolutionTTLOverride` (or 60s
by default) so the generated NetworkPolicy tracks IP changes automatically.
While resolution is cold (first reconcile, transient DNS errors) the controller
emits a deny-all-egress policy rather than a permissive no-op, so there is no
window where the pod is wide open. DNS egress (UDP/TCP port 53) is always
allowed on the generated policy so resolution can continue.

## Quick start

```bash
./demo.sh
```

`demo.sh` creates a `kind` cluster with Calico, builds and loads the controller
image, deploys everything, and proves enforcement by curling an allowed host and
a blocked host before and after the policy is applied. Takes 3-5 minutes; Calico
startup is the slow part. Tear down with:

```bash
kind delete cluster --name fqdn-demo
```

**Prerequisites:** `kind`, `kubectl`, `docker` on PATH.

## Writing a policy

```yaml
apiVersion: netsec.kunal.dev/v1alpha1
kind: FQDNNetworkPolicy
metadata:
  name: allow-stripe-and-github
  namespace: payments
spec:
  podSelector:
    podSelector:
      matchLabels:
        app: checkout-service
  egress:
    - match: api.stripe.com
      ports:
        - port: 443
          protocol: TCP
    - match: api.github.com
      ports:
        - port: 443
          protocol: TCP
  resolutionTTLOverride: 30   # re-resolve every 30s; omit to use DNS TTL (min 60s)
```

Apply it, then check what was generated:

```bash
kubectl -n payments get fqdnnetworkpolicy allow-stripe-and-github -o wide
kubectl -n payments get networkpolicy fqdnnp-allow-stripe-and-github -o yaml
```

The generated NetworkPolicy is named `fqdnnp-<your-policy-name>` and is
owned by the FQDNNetworkPolicy, so it is garbage-collected automatically when
you delete the CR.

### Spec reference

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `podSelector.podSelector` | `LabelSelector` | yes | Pods this policy applies to. Empty = all pods in the namespace. |
| `egress[].match` | string | yes | Hostname to allow. Exact names only; wildcard patterns (`*.example.com`) require the snoop resolver (not yet implemented). |
| `egress[].ports[].port` | int32 | yes | Destination port number. |
| `egress[].ports[].protocol` | string | no | `TCP`, `UDP`, or `SCTP`. Defaults to `TCP`. |
| `resolutionTTLOverride` | int32 | no | Re-resolution interval in seconds. Overrides observed DNS TTLs. |

### Status fields

```bash
kubectl -n payments get fqdnnetworkpolicy allow-stripe-and-github -o jsonpath='{.status}' | jq
```

| Field | Description |
|-------|-------------|
| `generatedNetworkPolicy` | Name of the managed NetworkPolicy. |
| `resolvedHosts[].hostname` | Hostname that was resolved. |
| `resolvedHosts[].ips` | IPs currently in the generated policy. |
| `resolvedHosts[].lastSeen` | Timestamp of last successful resolution. |
| `resolvedHosts[].source` | `active-lookup` (DNS query) or `dns-snoop` (eBPF capture). |
| `conditions[].type=Ready` | `True` when the NetworkPolicy is up to date. `False` with reason `ResolutionDegraded` on DNS errors (stale IPs are kept rather than revoking access on a transient blip). |

## Project layout

```
api/v1alpha1/
  fqdnnetworkpolicy_types.go      CRD types, kubebuilder markers
  zz_generated.deepcopy.go        generated — do not edit by hand

internal/dns/
  resolver.go                     ActiveResolver: live DNS lookups
  snoop_resolver.go               SnoopResolver: eBPF passive capture (stub)

internal/netpol/
  builder.go                      Converts resolved IPs → NetworkPolicy
  helpers.go                      hostCIDR: /32 for IPv4, /128 for IPv6

internal/controller/
  fqdnnetworkpolicy_controller.go Reconcile loop: resolve → build → apply → status

cmd/main.go                       Manager setup; swap Resolver implementation here

config/
  crd/bases/                      Generated CRD YAML
  rbac/role.yaml                  ClusterRole + ClusterRoleBinding for the controller
  manager/deployment.yaml         Namespace, ServiceAccount, Deployment
  samples/                        Example FQDNNetworkPolicy CR
```

## Development

### First-time setup

```bash
make build   # runs `make generate` then compiles the manager binary
```

`controller-gen` is downloaded to `./bin/` on first run (pinned version, no
global install needed).

### Codegen

Run `make generate manifests` after changing any CRD type, and commit the
result. Do not hand-edit `zz_generated.deepcopy.go` or
`config/crd/bases/*.yaml`; both are overwritten on the next generate run.

```bash
make generate   # regenerates zz_generated.deepcopy.go
make manifests  # regenerates config/crd/bases/*.yaml and config/rbac/role.yaml
```

> If you run `./demo.sh` after changing CRD types without running
> `make manifests` first, the CRD YAML the script applies will be stale
> relative to the types the controller compiled against.

### Run locally against a cluster

```bash
make run   # runs the manager binary against your current kubeconfig context
```

The controller uses your kubeconfig's current context. It will create and
update NetworkPolicies in whatever namespaces your FQDNNetworkPolicies live in.

### Validating a policy before applying

```bash
# Catch schema errors without touching the cluster:
kubectl apply -f my-policy.yaml --dry-run=client -o yaml

# Run admission webhooks against the live API server without persisting:
kubectl apply -f my-policy.yaml --dry-run=server
```

Neither dry-run mode triggers the controller's reconcile loop, so you will not
see resolved IPs or a generated NetworkPolicy until you apply for real.

## Known limitations

| Limitation | Workaround / plan |
|------------|-------------------|
| Wildcard FQDNs (`*.example.com`) are flagged and skipped | Requires `SnoopResolver` (eBPF DNS capture stub in `internal/dns/snoop_resolver.go`) |
| Single replica only; no leader election | Add `--leader-elect` flag in `cmd/main.go` before running multiple replicas |
| No metrics | Resolution failures are security-relevant; expose them via controller-runtime's built-in Prometheus endpoint before production use |
| Active DNS lookups only | `SnoopResolver` would catch IPs that pods contact before the TTL-based re-queue fires |
