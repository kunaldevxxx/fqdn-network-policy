#!/usr/bin/env bash
# demo.sh — spins up a real cluster, deploys the controller, and PROVES
# that FQDN-based egress control works on a non-Cilium CNI (Calico).
#
# This is written to be screen-recorded top to bottom: every step prints
# what it's doing and why, and the payoff (curl blocked vs curl allowed)
# is the last two commands.
#
# Requires: kind, kubectl, docker, calicoctl not needed (we use the
# Calico manifest directly).
set -euo pipefail

CLUSTER_NAME="fqdn-demo"
IMAGE_TAG="fqdn-network-policy:demo"
NS="payments"

section() { echo -e "\n\033[1;36m▶ $1\033[0m"; }

section "1. Create a kind cluster WITHOUT the default kindnet CNI"
cat <<EOF | kind create cluster --name "$CLUSTER_NAME" --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  disableDefaultCNI: true
EOF

section "2. Install Calico (kind's default CNI does NOT enforce NetworkPolicy)"
kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.28.0/manifests/calico.yaml
echo "waiting for Calico to be ready..."
# Calico uses hostNetwork so its pod starts before the node has a CNI.
# Once calico-node writes the CNI config the node flips to Ready — that is
# the reliable completion signal. Poll with short bursts to avoid a single
# long timeout that can fire before bootstrap finishes.
until kubectl wait node --all --for=condition=Ready --timeout=30s 2>/dev/null; do
  echo "  node not yet Ready, retrying..."
  sleep 10
done
kubectl -n kube-system rollout status daemonset/calico-node --timeout=60s

section "3. Install CRDs (FQDNNetworkPolicy + ClusterFQDNNetworkPolicy)"
kubectl apply -f config/crd/bases/

section "4. Build and load the controller image into kind"
docker build -t "$IMAGE_TAG" .
kind load docker-image "$IMAGE_TAG" --name "$CLUSTER_NAME"

section "5. Deploy the controller"
kubectl apply -f config/manager/deployment.yaml
kubectl apply -f config/rbac/role.yaml
kubectl apply -f config/rbac/role_binding.yaml
kubectl -n fqdn-network-policy-system rollout status deployment/fqdn-network-policy-controller --timeout=120s

section "6. Create the target namespace and a test pod"
kubectl create namespace "$NS" --dry-run=client -o yaml | kubectl apply -f -
kubectl -n "$NS" run checkout-service --image=curlimages/curl:8.9.1 \
  --labels="app=checkout-service" --command -- sleep infinity
kubectl -n "$NS" wait --for=condition=Ready pod/checkout-service --timeout=60s

section "7. BEFORE policy: pod can reach anything"
kubectl -n "$NS" exec checkout-service -- curl -sS -o /dev/null -w "api.stripe.com -> HTTP %{http_code}\n" https://api.stripe.com
kubectl -n "$NS" exec checkout-service -- curl -sS -o /dev/null -w "example.com   -> HTTP %{http_code}\n" https://example.com

section "8. Apply the FQDNNetworkPolicy: allow only api.stripe.com"
kubectl apply -f config/samples/netsec_v1alpha1_fqdnnetworkpolicy.yaml
echo "waiting for the controller to resolve hosts and generate a NetworkPolicy..."
NP_FOUND=false
for i in $(seq 1 30); do
  NP=$(kubectl -n "$NS" get networkpolicy fqdnnp-allow-stripe-and-github 2>/dev/null || true)
  if [ -n "$NP" ]; then
    echo "  NetworkPolicy generated (attempt $i)"
    NP_FOUND=true
    break
  fi
  echo "  attempt $i/30 — not yet, retrying in 2s..."
  sleep 2
done
if [ "$NP_FOUND" = false ]; then
  echo "WARNING: NetworkPolicy not seen after 60s — controller logs:"
  kubectl logs -n fqdn-network-policy-system \
    -l app=fqdn-network-policy-controller --tail=30
fi
kubectl -n "$NS" get fqdnnetworkpolicy allow-stripe-and-github -o wide
kubectl -n "$NS" get networkpolicy fqdnnp-allow-stripe-and-github -o yaml 2>/dev/null || true

section "9. AFTER policy: allowed host works, everything else is blocked"
set +e
kubectl -n "$NS" exec checkout-service -- curl -sS --max-time 5 -o /dev/null -w "api.stripe.com -> HTTP %{http_code}\n" https://api.stripe.com
# HTTP 000 means curl timed out — Calico dropped the packets (blocked)
kubectl -n "$NS" exec checkout-service -- curl -sS --max-time 5 -o /dev/null -w "example.com   -> HTTP %{http_code} (000 = blocked by NetworkPolicy)\n" https://example.com
set -e

section "10. Enable the ASN enricher and snoop resolver (both opt-in, off by default)"
kubectl -n fqdn-network-policy-system set env deployment/fqdn-network-policy-controller \
  FQDNNP_ASN_ENRICHER=ipinfo
kubectl -n fqdn-network-policy-system patch deployment fqdn-network-policy-controller \
  --type=json -p='[{"op":"add","path":"/spec/template/spec/containers/0/args","value":[
    "--enable-snoop-resolver=true",
    "--snoop-upstream=8.8.8.8:53"
  ]}]'
kubectl -n fqdn-network-policy-system rollout status deployment/fqdn-network-policy-controller --timeout=120s

section "11. Point CoreDNS at the snoop proxy so it sees real pod DNS traffic"
# The snoop proxy only sees what's forwarded to it; CoreDNS's own forward
# plugin needs to target it instead of the node resolver. It in turn
# forwards to 8.8.8.8 (set above) -- never back to CoreDNS, or every
# query would loop between the two forever.
# CoreDNS's forward plugin only accepts an IP address (or /etc/resolv.conf),
# not a Kubernetes Service DNS name -- resolve the snoop Service to its
# ClusterIP first.
SNOOP_IP=$(kubectl -n fqdn-network-policy-system get svc fqdn-network-policy-snoop -o jsonpath='{.spec.clusterIP}')
COREFILE_ORIG="$(mktemp)"
COREFILE_PATCHED="$(mktemp)"
kubectl -n kube-system get configmap coredns -o jsonpath='{.data.Corefile}' > "$COREFILE_ORIG"
sed -E "s#forward \.[^\{]*\{#forward . ${SNOOP_IP}:5353 {#" "$COREFILE_ORIG" > "$COREFILE_PATCHED"
kubectl -n kube-system create configmap coredns --from-file=Corefile="$COREFILE_PATCHED" \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl -n kube-system rollout restart deployment/coredns
kubectl -n kube-system rollout status deployment/coredns --timeout=60s

section "12. Create an FQDNEgressObservation"
# NOTE: observations are cluster-wide, not scoped to podSelector or this
# namespace. CoreDNS's forward plugin re-originates every forwarded query
# as its own client, so the snoop proxy can never see which pod actually
# asked -- only that a query happened. podSelector is accepted for forward
# compatibility (a future eBPF-based interceptor could honor it) but has
# no filtering effect today. See internal/dns/observation_store.go.
cat <<EOF | kubectl apply -f -
apiVersion: netsec.kunal.dev/v1alpha1
kind: FQDNEgressObservation
metadata:
  name: cluster-egress-observation
  namespace: $NS
spec:
  podSelector:
    podSelector:
      matchLabels:
        app: checkout-service
  observationWindow: 90s
EOF

section "13. Generate fresh DNS traffic through the snoop proxy"
kubectl -n "$NS" exec checkout-service -- curl -sS -o /dev/null -w "api.stripe.com -> HTTP %{http_code}\n" https://api.stripe.com
kubectl -n "$NS" exec checkout-service -- curl -sS -o /dev/null -w "api.github.com -> HTTP %{http_code}\n" https://api.github.com

# The FQDNEgressObservation controller re-reconciles every ~60s on its own,
# but its very first reconcile (right after creation, before the curls
# above ran) already saw zero domains and armed that 60s timer. An
# annotation-only update still triggers a reconcile (no generation-changed
# filter is applied), so nudge it now instead of waiting out the timer.
kubectl -n "$NS" annotate fqdnegressobservation cluster-egress-observation \
  netsec.kunal.dev/demo-kick="$(date +%s)" --overwrite >/dev/null

section "14. Wait for observed domains and ASN enrichment to land in status"
echo "waiting for FQDNEgressObservation to see the queries above..."
for i in $(seq 1 30); do
  DOMAINS=$(kubectl -n "$NS" get fqdnegressobservation cluster-egress-observation \
    -o jsonpath='{.status.observedDomains[*].hostname}' 2>/dev/null || true)
  [ -n "$DOMAINS" ] && { echo "  observed: $DOMAINS (attempt $i)"; break; }
  echo "  attempt $i/30 -- not yet, retrying in 2s..."
  sleep 2
done

echo "waiting for the ASN enricher's async background fetch to populate status..."
for i in $(seq 1 45); do
  ENRICHED=$(kubectl -n "$NS" get fqdnnetworkpolicy allow-stripe-and-github \
    -o jsonpath='{.status.resolvedHosts[0].ipEnrichments}' 2>/dev/null || true)
  [ -n "$ENRICHED" ] && { echo "  enriched (attempt $i)"; break; }
  echo "  attempt $i/45 -- not yet, retrying in 2s..."
  sleep 2
done

section "15. Show what got discovered"
echo "--- FQDNEgressObservation: hostnames observed cluster-wide ---"
kubectl -n "$NS" get fqdnegressobservation cluster-egress-observation -o yaml
echo "--- FQDNNetworkPolicy: ASN/org for each resolved IP ---"
kubectl -n "$NS" get fqdnnetworkpolicy allow-stripe-and-github -o go-template='
{{- range .status.resolvedHosts}}{{.hostname}}
{{- range $ip, $e := .ipEnrichments}}
  {{$ip}} -> {{$e.asn}} {{$e.org}} ({{$e.country}}){{end}}
{{end}}'

section "Done. Tear down with: kind delete cluster --name $CLUSTER_NAME"
