## What does this change do, and why?

<!-- Link the issue this addresses, if any: Closes #NNN -->

## Checklist

- [ ] If this touches a CRD type (`api/v1alpha1/*_types.go`): ran `make generate` and
      `make manifests`, and committed the regenerated `zz_generated.deepcopy.go` /
      `config/crd/bases/*.yaml` / `config/rbac/role.yaml`.
- [ ] If this adds a new RBAC need: added a `+kubebuilder:rbac` marker rather than hand-editing
      `config/rbac/role.yaml`.
- [ ] Added or updated tests (`go test -short -race ./...` passes locally).
- [ ] `go vet ./...` and `golangci-lint run` are clean.
- [ ] Updated `CHANGELOG.md` under `Unreleased`.
- [ ] Updated `README.md` if this changes user-facing behavior, flags, CRD fields, or metrics.
- [ ] If this is a new feature with an observable effect, ran `./demo.sh` (or a targeted manual
      check) against a real cluster — not just unit tests.

## How was this tested?

<!-- Unit tests added, demo.sh run output, manual kubectl output, etc. -->
