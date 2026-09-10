package profiler

import (
	"strings"
)

// Classification contains the human-readable category and provider name
// for an FQDN, providing immediate context in generated manifests and reports.
type Classification struct {
	Category string
	Provider string
}

type providerRule struct {
	suffix   string
	provider string
	category string
}

var knownProviders = []providerRule{
	// Payments & Financial
	{suffix: "stripe.com", provider: "Stripe", category: "Payments & Financial"},
	{suffix: "paypal.com", provider: "PayPal", category: "Payments & Financial"},
	{suffix: "adyen.com", provider: "Adyen", category: "Payments & Financial"},
	{suffix: "braintreegateway.com", provider: "Braintree", category: "Payments & Financial"},
	{suffix: "plaid.com", provider: "Plaid", category: "Payments & Financial"},
	{suffix: "squareup.com", provider: "Square", category: "Payments & Financial"},

	// Cloud & Storage
	{suffix: "amazonaws.com", provider: "AWS", category: "Cloud & Storage"},
	{suffix: "cloudfront.net", provider: "AWS CloudFront", category: "Cloud & Storage"},
	{suffix: "googleapis.com", provider: "Google Cloud", category: "Cloud & Storage"},
	{suffix: "googleusercontent.com", provider: "Google Cloud", category: "Cloud & Storage"},
	{suffix: "azure.com", provider: "Microsoft Azure", category: "Cloud & Storage"},
	{suffix: "azureedge.net", provider: "Microsoft Azure CDN", category: "Cloud & Storage"},
	{suffix: "windows.net", provider: "Microsoft Azure", category: "Cloud & Storage"},

	// Auth & Identity
	{suffix: "auth0.com", provider: "Auth0", category: "Auth & Identity"},
	{suffix: "okta.com", provider: "Okta", category: "Auth & Identity"},
	{suffix: "oktapreview.com", provider: "Okta", category: "Auth & Identity"},
	{suffix: "login.microsoftonline.com", provider: "Microsoft Entra ID", category: "Auth & Identity"},
	{suffix: "accounts.google.com", provider: "Google Identity", category: "Auth & Identity"},
	{suffix: "clerk.dev", provider: "Clerk", category: "Auth & Identity"},
	{suffix: "clerk.com", provider: "Clerk", category: "Auth & Identity"},

	// Observability & APM
	{suffix: "datadoghq.com", provider: "Datadog", category: "Observability & APM"},
	{suffix: "datadoghq.eu", provider: "Datadog", category: "Observability & APM"},
	{suffix: "sentry.io", provider: "Sentry", category: "Observability & APM"},
	{suffix: "honeycomb.io", provider: "Honeycomb", category: "Observability & APM"},
	{suffix: "newrelic.com", provider: "New Relic", category: "Observability & APM"},
	{suffix: "dynatrace.com", provider: "Dynatrace", category: "Observability & APM"},
	{suffix: "grafana.net", provider: "Grafana Cloud", category: "Observability & APM"},

	// Developer & Registries
	{suffix: "github.com", provider: "GitHub", category: "Developer & Registries"},
	{suffix: "githubusercontent.com", provider: "GitHub", category: "Developer & Registries"},
	{suffix: "gitlab.com", provider: "GitLab", category: "Developer & Registries"},
	{suffix: "docker.io", provider: "Docker Hub", category: "Developer & Registries"},
	{suffix: "docker.com", provider: "Docker", category: "Developer & Registries"},
	{suffix: "pypi.org", provider: "Python Package Index", category: "Developer & Registries"},
	{suffix: "pythonhosted.org", provider: "Python Package Index", category: "Developer & Registries"},
	{suffix: "npmjs.org", provider: "npm Registry", category: "Developer & Registries"},
	{suffix: "npmjs.com", provider: "npm Registry", category: "Developer & Registries"},
	{suffix: "crates.io", provider: "Rust Crates", category: "Developer & Registries"},

	// Communication & Messaging
	{suffix: "slack.com", provider: "Slack", category: "Communication & Messaging"},
	{suffix: "twilio.com", provider: "Twilio", category: "Communication & Messaging"},
	{suffix: "sendgrid.net", provider: "SendGrid", category: "Communication & Messaging"},
	{suffix: "mailgun.net", provider: "Mailgun", category: "Communication & Messaging"},

	// CDN & Edge Infrastructure
	{suffix: "cloudflare.com", provider: "Cloudflare", category: "CDN & Infrastructure"},
	{suffix: "fastly.net", provider: "Fastly", category: "CDN & Infrastructure"},
	{suffix: "akamai.net", provider: "Akamai", category: "CDN & Infrastructure"},
	{suffix: "akamaiedge.net", provider: "Akamai", category: "CDN & Infrastructure"},
	{suffix: "edgekey.net", provider: "Akamai", category: "CDN & Infrastructure"},
}

// ClassifyDomain returns the category and provider name for a given hostname or wildcard.
func ClassifyDomain(hostname string) Classification {
	hostname = strings.ToLower(strings.TrimSpace(hostname))
	hostname = strings.TrimPrefix(hostname, "*.")
	hostname = strings.TrimSuffix(hostname, ".")

	for _, rule := range knownProviders {
		if hostname == rule.suffix || strings.HasSuffix(hostname, "."+rule.suffix) {
			return Classification{
				Category: rule.category,
				Provider: rule.provider,
			}
		}
	}

	return Classification{
		Category: "General / Unclassified",
		Provider: BaseDomain(hostname),
	}
}
