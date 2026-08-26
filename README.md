# fqdn-network-policy

CNI-agnostic FQDN-based egress policy for Kubernetes. Write a rule like
`allow api.stripe.com`; the controller resolves it and reconciles a plain
`networking.k8s.io/v1 NetworkPolicy`, so enforcement works on Calico, AWS VPC
CNI, Azure CNI, or anything else that honors standard NetworkPolicy — no
CNI-specific dataplane required.

## Layout

```
api/v1alpha1/            CRD types: FQDNNetworkPolicy, status, conditions
internal/dns/            Pluggable resolvers behind the Resolver interface
  resolver.go               ActiveResolver: plain DNS lookups (start here)
  snoop_resolver.go         SnoopResolver: eBPF-based passive DNS capture (stub)
internal/netpol/         Builds the owned NetworkPolicy from resolved IPs
internal/controller/     Reconcile loop: resolve -> build -> apply -> status
cmd/main.go              Manager wiring; this is where Resolver gets swapped
config/samples/          Example CR
```

## Build order

1. Get `ActiveResolver` + the reconcile loop solid: create/update/status all
   working, deny-all-egress fallback while resolution is cold, DNS port 53
   always allowed so the policy doesn't lock out its own lookups.
2. Add a validating webhook that rejects wildcard `match` patterns until
   `SnoopResolver` exists (or accepts them with a `ResolutionDegraded`
   status condition instead of silently no-op'ing).
3. Implement `SnoopResolver`: a small privileged DaemonSet or eBPF probe
   attached to CoreDNS pods, feeding observed hostname->IP pairs back to
   the controller through a shared cache. No changes needed in
   `internal/controller` or `internal/netpol` since both are written
   against the `dns.Resolver` interface, not a concrete implementation.
4. Add CRD conversion/versioning once the v1alpha1 shape stabilizes.
5. Add e2e tests against kind with Calico (NetworkPolicy enforcement,
   unlike the default kind CNI, doesn't work out of the box otherwise).

## Running the demo

Run `make generate manifests` at least once before the first build — the
repo ships with the current generated output committed, so this is only
required again after you change a CRD type. `demo.sh` calls `docker build`
directly, not `make docker-build`, so if you've changed types since the
last generate, run `make manifests` first or the CRD YAML `demo.sh` applies
will be stale relative to the Go types the controller actually compiled
against.

`demo.sh` spins up a real kind cluster with Calico (kind's default CNI does
not enforce NetworkPolicy, so this step is required, not optional), builds
and loads the controller image, deploys everything, and proves enforcement
by curling an allowed host and a blocked host before and after the policy
is applied.

```bash
chmod +x demo.sh
./demo.sh
```

Takes 3-5 minutes, mostly Calico coming up. Tear down with:

```bash
kind delete cluster --name fqdn-demo
```

### Dry-running a policy before it goes live

Two options, from cheapest to most thorough:

1. **Client-side validation only** — catches typos and schema errors, no
   cluster state involved:
   ```bash
   kubectl apply -f my-policy.yaml --dry-run=client -o yaml
   ```
2. **Server-side dry run** — runs admission/validation against the live
   API server (and any webhook you add later) without persisting:
   ```bash
   kubectl apply -f my-policy.yaml --dry-run=server
   ```
   This does NOT trigger the controller's reconcile loop or actually
   resolve hostnames, since dry-run requests never hit informers. To see
   what NetworkPolicy a given FQDNNetworkPolicy *would* produce without
   applying it to real pods, the cleanest option is running the resolver
   and builder as a standalone CLI:
   ```bash
   go run ./cmd/main.go --dry-run --file=my-policy.yaml
   ```
   (Not implemented in this scaffold yet — wire `internal/netpol.Build`
   behind a flag that reads a YAML file instead of the API server and
   prints the generated NetworkPolicy to stdout. Small addition, useful
   for CI: run it in a pipeline to catch "this rule would deny-all"
   before merging.)

## Codegen (deepcopy, CRD YAML, RBAC)

This project uses `controller-gen`, driven by `+kubebuilder:*` markers
already present in `api/v1alpha1/fqdnnetworkpolicy_types.go` and
`internal/controller/fqdnnetworkpolicy_controller.go`. Three Makefile
targets cover it:

```bash
make generate   # regenerates api/v1alpha1/zz_generated.deepcopy.go
make manifests  # regenerates config/crd/bases/*.yaml and config/rbac/role.yaml
make build      # runs `generate` first, then `go build -o bin/manager ./cmd`
```

`controller-gen` itself is not a global install — `make controller-gen`
downloads a pinned version (`CONTROLLER_GEN_VERSION` in the Makefile) into
`./bin/`, so builds stay reproducible across machines and CI. First run
needs network access to fetch the tool; after that it's cached locally.

**Whenever you add, remove, or change a field on any CRD type**, run
`make generate manifests` again and commit the result. Don't hand-edit
`zz_generated.deepcopy.go` or `config/crd/bases/*.yaml` — both are
generated output and will be silently overwritten next run, and hand
edits drift from the actual struct definitions in ways that are easy to
miss (a forgotten deep-copy on a new slice field is a real, if subtle,
concurrency bug — the whole reason to generate this file rather than
write it by hand).

## Not yet in this scaffold

- Leader election wiring in `cmd/main.go` (flagged with a TODO) — needed
  before running more than one replica.
- Metrics: at minimum, expose resolution failures and NetworkPolicy
  reconcile latency; this is the kind of controller where a silent
  resolution failure is a security-relevant event, not just noise.
