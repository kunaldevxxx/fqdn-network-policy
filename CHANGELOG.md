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
