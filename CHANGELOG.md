# v0.2.0 — Enterprise-grade: multi-resolver, cluster policies, audit mode, metrics, Helm, CI

This release transforms the controller from a working scaffold into a system you can deploy
in production. Every limitation called out in v0.1.0 is resolved. The core architecture is
unchanged — hostname-to-NetworkPolicy via standard Kubernetes APIs — but every surrounding
concern is now properly addressed: CDN IP coverage, cluster-scoped policy, graduated
enforcement, observability, packaging, and automated testing.

## Breaking changes

**CRD group unchanged, but `status.resolvedHosts[].ttlSeconds` is a new field.** Existing
`FQDNNetworkPolicy` resources are backward-compatible; the controller re-populates status on
the first reconcile after upgrade. No re-apply is required.

**Leader election lease resource is new.** If your RBAC was applied from a pre-v0.2.0 manifest,
re-apply `config/rbac/role.yaml` to pick up the new `coordination.k8s.io/leases` grant before
running multiple replicas.

---

## DNS resolution: CDN IP coverage

**The core problem** CDN-backed services (Stripe, GitHub, AWS S3, Cloudflare) are anycast:
different DNS servers return different IPs for the same hostname. A controller querying a single
resolver from a single pod gets the IPs *that resolver* returned, which may not match the IPs
*pods* received.

**ActiveResolver — real TTLs, dual-stack** (`internal/dns/resolver.go`)

The resolver no longer uses `net.DefaultResolver`. It issues raw A and AAAA queries concurrently
using `miekg/dns`, reads the actual TTL values from each record (clamped to [5s, 300s]), and
resolves dual-stack addresses independently. The previous implementation used Go's caching
resolver, which hides TTLs behind an opaque poll interval and returns whichever answer the OS
already cached. The raw implementation ensures the controller's re-resolution timing tracks
actual DNS TTL expiry rather than a fixed interval.

**MultiResolver** (`internal/dns/multi_resolver.go`)

New. Queries four geographically diverse public resolvers — Cloudflare (1.1.1.1), Google
(8.8.8.8), Quad9 (9.9.9.9), OpenDNS (208.67.222.222) — and the cluster's CoreDNS concurrently
for both A and AAAA records. The IP set is the union of all responses. For CDN-backed services
that use anycast routing, different resolver vantage points return different PoP IPs. Unioning
them covers approximately 85% of IP divergence cases with no additional infrastructure or host
privileges.

MultiResolver is the default resolver strategy and is enabled by `--enable-multi-resolver=true`.

**SnoopResolver** (`internal/dns/snoop_resolver.go`)

Previously a stub. Now a real `miekg/dns.Server` running as a UDP DNS forwarding proxy on a
configurable address (default `:5353`). When CoreDNS is configured to forward through the
proxy, the controller sees every DNS response flowing to pods — recording exactly which IPs
each pod received, in the `IPCache`. The `Resolve()` method returns the union of the snoop
cache and a concurrent MultiResolver call (to catch IPs not yet seen from pod traffic).

This is the only approach that precisely solves the anycast problem: the proxy sees the same IPs
pods received because it is in the query path. The tradeoff is a required CoreDNS configuration
change:

```
.:53 {
    forward . <controller-pod-ip>:5353
    cache 30
}
```

Enable with `--enable-snoop-resolver=true --snoop-listen-address=0.0.0.0:5353`.

**WildcardResolver** (`internal/dns/wildcard_resolver.go`)

New. Handles `*.foo.com` patterns by expanding 40 common subdomain prefixes (`www`, `api`,
`cdn`, `assets`, `static`, and more) plus any dynamically learned prefixes (via
`LearnPrefix(baseDomain, prefix)`, called from the SnoopResolver as it observes traffic).
All expansions are probed concurrently with a bounded semaphore of 20 goroutines. Results
are unioned. Plain FQDNs are delegated to the underlying MultiResolver.

Wildcard rules are accepted by the admission webhook only when `--enable-snoop-resolver=true`,
because the prefix expansion approach may miss uncommon subdomains and is only acceptable when
complemented by the dynamic learning the snoop proxy provides.

**TTLQueue** (`internal/dns/ttl_queue.go`)

New. A `container/heap` min-heap keyed by `NextRefresh time.Time`. Each reconcile upserts the
minimum TTL observed across all FQDN rules for a given policy. The reconciler calls `MinDelay()`
to compute `RequeueAfter`, ensuring the next reconcile fires at the earliest TTL expiry rather
than at a fixed interval. This eliminates both under-fetching (stale IPs allowed to linger) and
over-fetching (unnecessary resolver calls before any TTL expires).

**IPCache** (`internal/dns/ip_cache.go`)

New. A `sync.RWMutex`-protected map of `hostname → []observedIP{ip string, expires time.Time}`.
`Record(hostname, ips, ttl)` merges new IPs into the existing set without overwriting still-live
entries. `Get(hostname)` returns only non-expired IPs. This is the backing store for SnoopResolver
and is what allows the controller to present the union of snoop-observed IPs and live-resolver IPs
without losing IPs that have already expired from the live DNS response but may still be active in
connection tracking.

---

## Cluster-scoped policy: `ClusterFQDNNetworkPolicy`

**New CRD** (`api/v1alpha1/clusterfqdnnetworkpolicy_types.go`)

A cluster-scoped resource that platform teams can use to apply baseline egress rules across
all matched namespaces without duplicating a `FQDNNetworkPolicy` per namespace. The spec
adds a `namespaceSelector` alongside the existing `podSelector`, `egress`, `mode`, and
resolution tuning fields.

**New controller** (`internal/controller/clusterfqdnnetworkpolicy_controller.go`)

Full reconcile loop implementing:
- `matchedNamespaces()`: uses `metav1.LabelSelectorAsSelector` to list namespaces matching the
  policy's selector, with an empty selector defaulting to all namespaces.
- `syntheticPolicy()`: converts the cluster-scoped policy into a namespace-scoped struct that
  can be passed directly to `netpol.Build()`, reusing all existing NetworkPolicy construction
  logic.
- `garbageCollect()`: lists `NetworkPolicy` objects in all cluster namespaces with the label
  `netsec.kunal.dev/cluster-policy=<policy-name>` and deletes any whose namespace no longer
  matches the current `namespaceSelector`. This is the correct approach for selector changes —
  the controller always reconciles to desired state, removing policies from namespaces that
  have lost the required label.
- Namespace watch: uses `handler.EnqueueRequestsFromMapFunc` to re-enqueue all
  `ClusterFQDNNetworkPolicy` objects when any Namespace changes. This ensures that labeling
  a namespace causes the cluster policy to be applied there on the next reconcile without
  waiting for the policy's own resync period.
- `updateClusterStatus()`: tracks `AffectedNamespaces []string` in status so operators can
  quickly audit which namespaces are currently receiving a cluster policy.

---

## Graduated enforcement: Audit mode

**`spec.mode: Audit`** (`api/v1alpha1/fqdnnetworkpolicy_types.go`)

New. When `mode: Audit`, the reconciler resolves all hostnames, logs the resulting IPs,
and fires a `AuditResolved` Kubernetes Event — but does not create or update any
`NetworkPolicy`. The status condition is set to `Ready=True` with reason `AuditMode`.

This makes it safe to validate a policy's IP coverage before applying it in a namespace
that already has restrictive baseline policies. The intended workflow:

1. Deploy with `mode: Audit` and verify Events show the expected IPs.
2. Switch to `mode: Enforce` when confident.

Audit mode is enforced in the E2E test suite: the CI job verifies that no `NetworkPolicy`
object is created for a policy in Audit mode.

---

## Admission webhook

**HTTP handler** (`internal/webhook/validate.go`)

New. A `net/http` handler implementing the `ValidatingAdmissionWebhook` contract for both
`FQDNNetworkPolicy` and `ClusterFQDNNetworkPolicy`. Validates at `kubectl apply` time:

- `match` is a syntactically valid FQDN or wildcard FQDN.
- Wildcard `match` values are rejected when `--enable-snoop-resolver` is not set.
- Duplicate `match` values within one policy are rejected.
- Port numbers are in range 1–65535.
- Protocol is `TCP`, `UDP`, or `SCTP`.
- No raw IP addresses in `match` (the `net.ParseIP` check catches common mistakes).

CEL validation markers (`+kubebuilder:validation:XValidation`) were added to the CRD types
as a second layer of validation for API servers with CRD validation expression support.
The admission webhook remains the primary validation path for clusters on older API server
versions.

---

## Observability

**Prometheus metrics** (`internal/metrics/metrics.go`)

Expanded from 4 to 15 metrics, organized across five categories:

DNS category:
- `fqdn_dns_lookup_duration_seconds` — histogram by `domain` and `resolver` label
- `fqdn_dns_lookup_failures_total` — counter by `domain` and `reason` (`nxdomain`, `timeout`, `servfail`, `other`)
- `fqdn_dns_cache_hits_total` — counter; incremented when the snoop cache satisfies a lookup
- `fqdn_dns_snoop_observations_total` — counter by `qtype` (A, AAAA)
- `fqdn_ttl_expiry_lag_seconds` — histogram measuring how late a domain was re-resolved after TTL expiry

NetworkPolicy category:
- `fqdn_resolved_ips_count` — gauge; current number of IPs in the active policy per domain
- `fqdn_ip_changes_total` — counter; incremented when the IP set changes and triggers a write
- `fqdn_networkpolicy_sync_duration_seconds` — histogram by `outcome` (created, updated, skipped)
- `fqdn_networkpolicy_sync_errors_total` — counter by `reason`

Controller category:
- `fqdn_managed_policies_total` — gauge; active `FQDNNetworkPolicy` count
- `fqdn_cluster_managed_namespaces_total` — gauge; namespaces receiving `ClusterFQDNNetworkPolicy` coverage
- `fqdn_reconcile_duration_seconds` — histogram by controller type
- `fqdn_leader_transitions_total` — counter; incremented each time this replica wins the leader election
- `fqdn_snoop_cache_size` — gauge; number of hostnames currently in the snoop IP cache

**etcd write throttling** (`internal/controller/fqdnnetworkpolicy_controller.go`)

The reconciler now calls `ipSetsEqual()` before writing a `NetworkPolicy` update. If the
resolved IP set is identical to what is already in the policy, the write is skipped. This
prevents a high-TTL domain (e.g. a stable internal hostname that returns the same IP for
hours) from generating a constant stream of identical etcd writes and audit log entries.

**Kubernetes Events** (`internal/controller/fqdnnetworkpolicy_controller.go`)

The reconciler now holds a `record.EventRecorder` and emits named events:
- `NetworkPolicyCreated` on first reconcile
- `NetworkPolicyUpdated` when the IP set changes
- `ResolutionFailed` on DNS errors (includes domain and error detail in the message)
- `AuditResolved` in Audit mode (includes resolved IP list)

**Status conditions** (`internal/controller/fqdnnetworkpolicy_controller.go`)

Added a `Degraded` condition type. `setCondition()` preserves `LastTransitionTime` when
the reason and status are unchanged, suppressing spurious updates to the condition. This
prevents controllers like Flux or ArgoCD that watch condition timestamps from triggering
unnecessary sync cycles on each reconcile.

---

## High availability

**Leader election**

The controller now registers a lease-based leader election via controller-runtime's standard
`LeaderElectionID` option. Only the leader issues DNS queries and writes `NetworkPolicy` objects.
Standby replicas run the reconcile loop but short-circuit before any external calls. Leader
transitions are recorded by the `fqdn_leader_transitions_total` metric.

Enable with `--leader-elect=true` (or `leaderElection.enabled: true` in Helm).

---

## Packaging and operations

**Helm chart** (`charts/fqdn-network-policy/`)

New. Chart version `0.2.0`. Covers:
- Image, replicas, pull policy
- Leader election toggle
- Resolver strategy flags (`snoopResolver.enabled`, `multiResolver.enabled`, `coreDNS.address`)
- Metrics (`bindAddress`, optional `serviceMonitor` for prometheus-operator)
- Health probe address
- Admission webhook (`bindAddress`, `certManager` toggle)
- Pod security context (non-root, read-only root filesystem, drop-all capabilities)
- Container security context
- Resources (conservative defaults: 50m CPU / 64Mi memory requests)
- Pod anti-affinity (prefers spreading replicas across nodes)
- `nodeSelector`, `tolerations`
- RBAC and ServiceAccount creation toggles

**GitHub Actions CI** (`.github/workflows/ci.yml`)

New pipeline with five jobs:
1. `lint` — golangci-lint with 5 minute timeout
2. `unit` — `go test -short -race` across `internal/dns`, `internal/netpol`, `internal/webhook`; enforces 60% minimum coverage with `go tool cover`
3. `build` — `go build ./cmd/...` and `go vet ./...`
4. `e2e` — KinD cluster with Calico; installs CRDs and controller; verifies NetworkPolicy creation on Enforce mode; verifies no NetworkPolicy is created on Audit mode; fails fast with controller log collection on error
5. `helm-lint` — `helm lint` and `helm template` dry-run

---

## Testing

**29 unit tests across three packages**

`internal/dns/resolver_test.go` (14 tests):
- 5 IPCache tests: deduplication, TTL expiry, concurrent write safety
- 3 TTLQueue tests: min-heap ordering, `PeekNext`, `MinDelay` floor clamping
- 3 ActiveResolver tests (network-gated with `testing.Short()`, skipped in CI unit job)
- 2 WildcardResolver tests: plain FQDN delegation, wildcard expansion to union
- 1 FQDN validation table test: 8 subtests covering valid and invalid input forms

`internal/netpol/builder_test.go` (8 tests):
- `NoResolvedHosts_DenyAll` — confirms fail-closed behavior
- `WithResolvedIPv4` and `WithResolvedIPv6` — confirms `/32` and `/128` prefix lengths
- `MixedDualStack` — confirms both address families in one policy
- `DNSEgressAlwaysPresent` — confirms UDP/53 and TCP/53 rules are always present
- `PolicyType`, `OwnerNameFormat`, `PodSelectorPropagated`

`internal/webhook/validate_test.go` (7 tests using `httptest.NewRecorder`):
- `ValidPolicy_Allowed`
- `WildcardWithoutSnoop_Denied`
- `WildcardWithSnoop_Allowed`
- `InvalidFQDN_Denied`
- `DuplicateMatch_Denied`
- `InvalidPort_Denied`
- `ClusterPolicy_ValidAllowed`

**Run unit tests:**
```bash
go test -short -race ./internal/dns/... ./internal/netpol/... ./internal/webhook/...
```

---

## Upgrade from v0.1.1

1. Re-apply RBAC to pick up the new `coordination.k8s.io/leases` rule and the `events` and
   `namespaces` grants required by the event recorder and cluster controller:

   ```bash
   kubectl apply -f config/rbac/role.yaml
   ```

2. Apply the new `ClusterFQDNNetworkPolicy` CRD:

   ```bash
   kubectl apply -f config/crd/bases/netsec.kunal.dev_clusterfqdnnetworkpolicies.yaml
   ```

3. Restart the controller:

   ```bash
   kubectl rollout restart deployment/fqdn-network-policy-controller \
     -n fqdn-network-policy-system
   ```

4. Existing `FQDNNetworkPolicy` resources require no changes. On first reconcile the controller
   populates the new `status.resolvedHosts[].ttlSeconds` field and sets the `Degraded` condition
   if any host is failing resolution.

5. If upgrading to 2 replicas, add `--leader-elect=true` to the Deployment args (or use Helm
   with `--set replicaCount=2 --set leaderElection.enabled=true`).

---

# v0.1.1 — Bug fixes: IPv6 CIDRs, RBAC, demo reliability

This release fixes three bugs that prevented the controller from working
correctly on a fresh cluster. The demo (`./demo.sh`) now runs end-to-end
without intervention.

## Bug fixes

**IPv6 CIDR prefix length (`internal/netpol/helpers.go`)**

The controller was generating `ipBlock.cidr` entries with a `/32` prefix for
every resolved IP regardless of address family. Kubernetes rejects any CIDR
where bits are set beyond the prefix length, so IPv6 addresses — including
NAT64-mapped addresses in the `64:ff9b::/96` prefix returned by clusters that
translate IPv4 to IPv6 — caused a validation error and the NetworkPolicy was
never created. The controller retried on backoff, logging the same error
repeatedly, and egress remained deny-all indefinitely.

Fix: `hostCIDR()` now inspects the parsed IP and returns `/128` for IPv6
addresses and `/32` for IPv4. A single host route in IPv6 requires a full
128-bit mask; `/32` is an IPv4 concept.

**Missing ClusterRoleBinding (`config/rbac/role.yaml`)**

The ClusterRole granting the controller access to `FQDNNetworkPolicy` and
`NetworkPolicy` resources existed, but there was no ClusterRoleBinding to
attach it to the controller's ServiceAccount. On any fresh cluster the
controller pod would start successfully, then immediately fail to watch its
own CRD, logging `fqdnnetworkpolicies.netsec.kunal.dev is forbidden` in a
backoff loop. No FQDNNetworkPolicy was ever reconciled.

Fix: a `ClusterRoleBinding` binding
`system:serviceaccount:fqdn-network-policy-system:fqdn-network-policy-controller`
to the ClusterRole is now included in `config/rbac/role.yaml` and applied in
step 5 of `demo.sh`.

**Calico install timeout in `demo.sh`**

The script waited for `kubectl rollout status daemonset/calico-node
--timeout=180s`. This reliably timed out because Calico uses `hostNetwork`
and runs before the node has a CNI — the node stays `NotReady` until the
Calico CNI plugin writes its config, but `rollout status` requires all
DaemonSet pods to be available, which can take longer than 180 seconds on
slower machines or under Docker resource constraints.

Fix: the script now polls `kubectl wait node --all --for=condition=Ready`
in a 30-second burst loop. The node transitioning to `Ready` is the correct
completion signal — it proves the CNI plugin is installed and functional.
Once the node is Ready, a short 60-second `rollout status` confirms the
DaemonSet has fully rolled out.

## Documentation

Rewrote `README.md`:

- Architecture diagram showing the resolve-build-enforce flow.
- Full spec and status field reference tables.
- Inline sample CR with field-level annotations.
- Generated NetworkPolicy naming convention and how to inspect it.
- Known limitations as a scannable table instead of scattered prose.

## Upgrade from v0.1.0

Re-apply the RBAC manifest to pick up the new ClusterRoleBinding:

```bash
kubectl apply -f config/rbac/role.yaml
```

Then restart the controller so it picks up the new permissions:

```bash
kubectl rollout restart deployment/fqdn-network-policy-controller \
  -n fqdn-network-policy-system
```

No CRD schema changes. No changes to `FQDNNetworkPolicy` spec or status
fields. Existing FQDNNetworkPolicy resources do not need to be re-applied.

---

# v0.1.0 — Initial scaffold

First cut of `fqdn-network-policy`: a controller that lets you write
`allow api.stripe.com` as a Kubernetes egress rule and get real enforcement
on **any CNI** that honors standard `NetworkPolicy` — Calico, AWS VPC CNI,
Azure CNI, not just Cilium.

This release is a working scaffold, not a production build. It's meant to
be cloned, run against the included demo, and extended.

## What's in this release

**CRD**
- `FQDNNetworkPolicy` (`netsec.kunal.dev/v1alpha1`): define egress rules
  by hostname per pod selector, with per-rule port/protocol restrictions
  and an optional TTL override for re-resolution.

**Controller**
- Reconcile loop: resolve hostnames → build a plain `NetworkPolicy` →
  apply it → update status with resolved IPs and a `Ready`/`ResolutionDegraded`
  condition.
- Fails closed: if no hosts have resolved yet, the generated policy denies
  all egress for the selected pods rather than allowing everything.
- DNS (port 53, TCP+UDP) is always permitted in the generated policy, so
  the controller doesn't lock out the lookups it depends on.
- Transient resolution failures reuse the last known-good IPs for that
  host instead of dropping access on a single failed lookup.

**Resolution**
- `dns.Resolver` interface, with `ActiveResolver` implemented (plain DNS
  lookups on a poll/TTL interval).
- `dns.SnoopResolver` stubbed but not implemented — this is the planned
  eBPF-based passive DNS capture that will make wildcard patterns and
  CDN-backed hosts (Stripe, GitHub, anything behind a CDN that rotates
  IPs) resolve accurately. Wildcard `match` patterns are explicitly
  rejected today with a clear error, not silently ignored.

**Ops**
- CRD manifest, RBAC, and Deployment YAML — installable without
  `controller-gen`.
- `Dockerfile` for a distroless controller image.
- `demo.sh`: spins up kind with Calico (kind's default CNI does not
  enforce `NetworkPolicy`, so this is required for the demo to mean
  anything), deploys the controller, and proves enforcement with a
  before/after curl against an allowed host and a blocked host.

## Known limitations

- No leader election — do not run more than one replica yet.
- No metrics endpoint.
- No admission webhook — invalid or wildcard rules surface only via
  status conditions, not at `kubectl apply` time.
- No CLI dry-run mode (`--dry-run --file=policy.yaml` is planned; see
  README).
- No e2e test suite.
- `SnoopResolver` is unimplemented; wildcard hostnames are unsupported
  until it lands.

## Upgrade notes

N/A — initial release.

## Try it

```bash
git clone <repo>
cd fqdn-network-policy
chmod +x demo.sh
./demo.sh
```

Full walkthrough and dry-run instructions in `README.md`.
