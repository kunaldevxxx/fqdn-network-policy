// Package enrich implements an optional, opt-in ASN/organization enricher
// for resolved IPs. Disabled by default: the controller makes zero external
// calls unless FQDNNP_ASN_ENRICHER=ipinfo is set. See Issue #9.
package enrich

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const defaultIPInfoBaseURL = "https://ipinfo.io"

// Result is one IP's ASN/org lookup result.
type Result struct {
	ASN     string
	Org     string
	Country string
}

// Client looks up ASN/org metadata for a single IP address.
type Client interface {
	Lookup(ctx context.Context, ip string) (Result, error)
}

// IPInfoClient queries the ipinfo.io API (or a compatible mock in tests).
type IPInfoClient struct {
	// BaseURL defaults to https://ipinfo.io. Overridable for tests.
	BaseURL string
	// Token is the optional ipinfo.io API token for higher rate limits.
	Token string
	// HTTPClient defaults to a client with a 5s timeout.
	HTTPClient *http.Client
}

// NewIPInfoClient returns an IPInfoClient configured with the given token
// (may be empty for unauthenticated, lower-rate-limit requests).
func NewIPInfoClient(token string) *IPInfoClient {
	return &IPInfoClient{
		BaseURL:    defaultIPInfoBaseURL,
		Token:      token,
		HTTPClient: &http.Client{Timeout: 5 * time.Second},
	}
}

// ipInfoResponse mirrors the subset of ipinfo.io's JSON response we use.
// The "org" field combines the ASN and organization name, e.g.
// "AS15169 Google LLC".
type ipInfoResponse struct {
	Org     string `json:"org"`
	Country string `json:"country"`
}

func (c *IPInfoClient) Lookup(ctx context.Context, ip string) (Result, error) {
	baseURL := c.BaseURL
	if baseURL == "" {
		baseURL = defaultIPInfoBaseURL
	}
	httpClient := c.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 5 * time.Second}
	}

	reqURL := fmt.Sprintf("%s/%s/json", strings.TrimSuffix(baseURL, "/"), url.PathEscape(ip))
	if c.Token != "" {
		reqURL += "?token=" + url.QueryEscape(c.Token)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return Result{}, err
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return Result{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return Result{}, fmt.Errorf("ipinfo lookup for %s: unexpected status %d", ip, resp.StatusCode)
	}

	var parsed ipInfoResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return Result{}, fmt.Errorf("ipinfo lookup for %s: decode response: %w", ip, err)
	}

	asn, org := splitASNOrg(parsed.Org)
	return Result{ASN: asn, Org: org, Country: parsed.Country}, nil
}

// splitASNOrg splits ipinfo's combined "org" field ("AS15169 Google LLC")
// into its ASN ("AS15169") and organization name ("Google LLC") parts.
func splitASNOrg(combined string) (asn, org string) {
	if combined == "" {
		return "", ""
	}
	fields := strings.SplitN(combined, " ", 2)
	if len(fields) == 2 && strings.HasPrefix(fields[0], "AS") {
		return fields[0], fields[1]
	}
	return "", combined
}
