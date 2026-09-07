package enrich_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kunaldevxxx/fqdn-network-policy/internal/enrich"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockIPInfoServer returns an httptest.Server that mimics ipinfo.io's
// GET /{ip}/json response shape.
func mockIPInfoServer(t *testing.T, org, country string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"ip":      "1.2.3.4",
			"org":     org,
			"country": country,
		})
	}))
}

func TestIPInfoClient_Lookup_ParsesASNAndOrg(t *testing.T) {
	server := mockIPInfoServer(t, "AS15169 Google LLC", "US")
	defer server.Close()

	client := &enrich.IPInfoClient{BaseURL: server.URL}
	result, err := client.Lookup(context.Background(), "8.8.8.8")
	require.NoError(t, err)
	assert.Equal(t, "AS15169", result.ASN)
	assert.Equal(t, "Google LLC", result.Org)
	assert.Equal(t, "US", result.Country)
}

func TestIPInfoClient_Lookup_OrgWithoutASNPrefix(t *testing.T) {
	server := mockIPInfoServer(t, "Some Hosting Provider", "DE")
	defer server.Close()

	client := &enrich.IPInfoClient{BaseURL: server.URL}
	result, err := client.Lookup(context.Background(), "5.6.7.8")
	require.NoError(t, err)
	assert.Empty(t, result.ASN, "no AS-prefixed token: ASN should stay empty rather than misparsed")
	assert.Equal(t, "Some Hosting Provider", result.Org)
}

func TestIPInfoClient_Lookup_NonOKStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()

	client := &enrich.IPInfoClient{BaseURL: server.URL}
	_, err := client.Lookup(context.Background(), "1.1.1.1")
	assert.Error(t, err)
}

func TestIPInfoClient_Lookup_SendsToken(t *testing.T) {
	var gotToken string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotToken = r.URL.Query().Get("token")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"org": "AS1 Test", "country": "US"})
	}))
	defer server.Close()

	client := &enrich.IPInfoClient{BaseURL: server.URL, Token: "secret-token"}
	_, err := client.Lookup(context.Background(), "1.1.1.1")
	require.NoError(t, err)
	assert.Equal(t, "secret-token", gotToken)
}
