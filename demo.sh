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

section "Done. Tear down with: kind delete cluster --name $CLUSTER_NAME"
