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
kubectl -n kube-system rollout status daemonset/calico-node --timeout=180s

section "3. Install the FQDNNetworkPolicy CRD"
kubectl apply -f config/crd/bases/netsec.kunal.dev_fqdnnetworkpolicies.yaml

section "4. Build and load the controller image into kind"
docker build -t "$IMAGE_TAG" .
kind load docker-image "$IMAGE_TAG" --name "$CLUSTER_NAME"

section "5. Deploy the controller"
kubectl apply -f config/manager/deployment.yaml
kubectl apply -f config/rbac/role.yaml
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
sleep 5
kubectl -n "$NS" get fqdnnetworkpolicy allow-stripe-and-github -o wide
kubectl -n "$NS" get networkpolicy

section "9. AFTER policy: allowed host works, everything else is blocked"
set +e
kubectl -n "$NS" exec checkout-service -- curl -sS --max-time 5 -o /dev/null -w "api.stripe.com -> HTTP %{http_code}\n" https://api.stripe.com
kubectl -n "$NS" exec checkout-service -- curl -sS --max-time 5 -o /dev/null -w "example.com   -> %{errormsg}\n" https://example.com
set -e

section "Done. Tear down with: kind delete cluster --name $CLUSTER_NAME"
