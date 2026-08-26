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
