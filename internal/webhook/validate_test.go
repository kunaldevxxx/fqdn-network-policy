package webhook_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	netv1alpha1 "github.com/kunaldevxxx/fqdn-network-policy/api/v1alpha1"
	"github.com/kunaldevxxx/fqdn-network-policy/internal/webhook"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
)

func reviewFor(t *testing.T, obj interface{}) *bytes.Buffer {
	t.Helper()
	raw, err := json.Marshal(obj)
	require.NoError(t, err)
	review := admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{APIVersion: "admission.k8s.io/v1", Kind: "AdmissionReview"},
		Request: &admissionv1.AdmissionRequest{
			UID:    types.UID("test-uid"),
			Object: runtime.RawExtension{Raw: raw},
		},
	}
	body, err := json.Marshal(review)
	require.NoError(t, err)
	return bytes.NewBuffer(body)
}

func postReview(t *testing.T, handler http.Handler, path string, body *bytes.Buffer) *admissionv1.AdmissionReview {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, body)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)
	var out admissionv1.AdmissionReview
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&out))
	require.NotNil(t, out.Response)
	return &out
}

// ── FQDNNetworkPolicy admission ────────────────────────────────────────────

func TestWebhook_ValidPolicy_Allowed(t *testing.T) {
	h := webhook.Handler(webhook.Config{SnoopEnabled: false})
	fp := netv1alpha1.FQDNNetworkPolicy{
		Spec: netv1alpha1.FQDNNetworkPolicySpec{
			Egress: []netv1alpha1.FQDNRule{
				{Match: "api.stripe.com", Ports: []netv1alpha1.PolicyPort{{Port: 443, Protocol: "TCP"}}},
			},
		},
	}
	out := postReview(t, h, "/validate/fqdnnetworkpolicy", reviewFor(t, fp))
	assert.True(t, out.Response.Allowed)
}

func TestWebhook_WildcardWithoutSnoop_Denied(t *testing.T) {
	h := webhook.Handler(webhook.Config{SnoopEnabled: false})
	fp := netv1alpha1.FQDNNetworkPolicy{
		Spec: netv1alpha1.FQDNNetworkPolicySpec{
			Egress: []netv1alpha1.FQDNRule{{Match: "*.googleapis.com"}},
		},
	}
	out := postReview(t, h, "/validate/fqdnnetworkpolicy", reviewFor(t, fp))
	assert.False(t, out.Response.Allowed)
	assert.Contains(t, out.Response.Result.Message, "wildcard")
}

func TestWebhook_WildcardWithSnoop_Allowed(t *testing.T) {
	h := webhook.Handler(webhook.Config{SnoopEnabled: true})
	fp := netv1alpha1.FQDNNetworkPolicy{
		Spec: netv1alpha1.FQDNNetworkPolicySpec{
			Egress: []netv1alpha1.FQDNRule{{Match: "*.googleapis.com"}},
		},
	}
	out := postReview(t, h, "/validate/fqdnnetworkpolicy", reviewFor(t, fp))
	assert.True(t, out.Response.Allowed)
}

func TestWebhook_InvalidFQDN_Denied(t *testing.T) {
	h := webhook.Handler(webhook.Config{})
	fp := netv1alpha1.FQDNNetworkPolicy{
		Spec: netv1alpha1.FQDNNetworkPolicySpec{
			Egress: []netv1alpha1.FQDNRule{{Match: "not a valid domain!"}},
		},
	}
	out := postReview(t, h, "/validate/fqdnnetworkpolicy", reviewFor(t, fp))
	assert.False(t, out.Response.Allowed)
}

func TestWebhook_DuplicateMatch_Denied(t *testing.T) {
	h := webhook.Handler(webhook.Config{})
	fp := netv1alpha1.FQDNNetworkPolicy{
		Spec: netv1alpha1.FQDNNetworkPolicySpec{
			Egress: []netv1alpha1.FQDNRule{
				{Match: "api.example.com"},
				{Match: "api.example.com"},
			},
		},
	}
	out := postReview(t, h, "/validate/fqdnnetworkpolicy", reviewFor(t, fp))
	assert.False(t, out.Response.Allowed)
	assert.Contains(t, out.Response.Result.Message, "duplicate")
}

func TestWebhook_InvalidPort_Denied(t *testing.T) {
	h := webhook.Handler(webhook.Config{})
	fp := netv1alpha1.FQDNNetworkPolicy{
		Spec: netv1alpha1.FQDNNetworkPolicySpec{
			Egress: []netv1alpha1.FQDNRule{
				{Match: "api.example.com", Ports: []netv1alpha1.PolicyPort{{Port: 99999, Protocol: "TCP"}}},
			},
		},
	}
	out := postReview(t, h, "/validate/fqdnnetworkpolicy", reviewFor(t, fp))
	assert.False(t, out.Response.Allowed)
}

func TestWebhook_HealthzEndpoint(t *testing.T) {
	h := webhook.Handler(webhook.Config{})
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
}

// ── ClusterFQDNNetworkPolicy admission ────────────────────────────────────

func TestWebhook_ClusterPolicy_ValidAllowed(t *testing.T) {
	h := webhook.Handler(webhook.Config{SnoopEnabled: true})
	cp := netv1alpha1.ClusterFQDNNetworkPolicy{
		Spec: netv1alpha1.ClusterFQDNNetworkPolicySpec{
			Egress: []netv1alpha1.FQDNRule{
				{Match: "*.s3.amazonaws.com", Ports: []netv1alpha1.PolicyPort{{Port: 443, Protocol: "TCP"}}},
			},
		},
	}
	out := postReview(t, h, "/validate/clusterfqdnnetworkpolicy", reviewFor(t, cp))
	assert.True(t, out.Response.Allowed)
}
