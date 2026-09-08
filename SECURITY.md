# Security Policy

fqdn-network-policy is a network security control: it generates `NetworkPolicy` objects that
gate egress traffic. A vulnerability here can mean traffic that should be blocked gets allowed
(or vice versa), so please report issues privately rather than filing a public GitHub issue.

## Supported versions

| Version | Supported |
|---------|-----------|
| `main` (unreleased) | Yes |
| Latest tagged release (`v0.2.x`) | Yes |
| Older tagged releases | Best effort — please upgrade |

## Reporting a vulnerability

Preferred: use GitHub's private reporting flow — go to the
[Security tab](https://github.com/kunaldevxxx/fqdn-network-policy/security/advisories/new) and
click "Report a vulnerability." This opens a private advisory only maintainers can see.

Alternatively, email **kunalkhare2004@gmail.com** with:

- A description of the vulnerability and its impact (e.g. "a crafted DNS response causes the
  controller to allow-list an unintended IP range").
- Steps to reproduce, including the resolver mode in use (`ActiveResolver`, `MultiResolver`,
  `CoreDNSResolver`, or `SnoopResolver`) and relevant `FQDNNetworkPolicy`/`SecuritySpec` config.
- Your assessment of severity, if you have one.

Please do not open a public issue, discussion, or PR that discloses the vulnerability before a
fix is available.

## What to expect

- Acknowledgement within 5 business days.
- An initial assessment (confirmed / not a vulnerability / needs more info) within 10 business
  days.
- Credit in the release notes and `CHANGELOG.md` once a fix ships, unless you'd prefer to stay
  anonymous.

## Scope

In scope: the controller (`cmd/`, `internal/`), the CRDs and their validation webhook, the
`kubectl-fqdn_policy` plugin, and the Helm chart under `charts/`.

Out of scope: vulnerabilities in upstream dependencies (please report those to the relevant
project — `go.mod`/`go.sum` pin the versions in use) and misconfiguration of the cluster itself
(e.g. a CNI that doesn't enforce `NetworkPolicy` at all — see the comparison table in
[README.md](README.md#how-it-compares)).
