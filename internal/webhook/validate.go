// Package webhook provides the HTTP handler for the ValidatingAdmissionWebhook.
// It validates FQDNNetworkPolicy and ClusterFQDNNetworkPolicy objects before
// they are persisted to etcd, catching errors CEL markers miss — wildcards when
// SnoopResolver is disabled, duplicate rules, port range violations.
package webhook

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"

	admissionv1 "k8s.io/api/admission/v1"
	netv1alpha1 "github.com/kunaldevxxx/fqdn-network-policy/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

var fqdnRE = regexp.MustCompile(`^(\*\.)?([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)

// Config holds runtime settings the webhook needs for context-aware decisions.
type Config struct {
	// SnoopEnabled indicates the SnoopResolver proxy is active.
	// When false, wildcard FQDNs are rejected because they cannot be expanded.
	SnoopEnabled bool
}

// Handler returns an http.Handler serving the webhook validation endpoints.
func Handler(cfg Config) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/validate/fqdnnetworkpolicy", admitFQDNNetworkPolicy(cfg))
	mux.HandleFunc("/validate/clusterfqdnnetworkpolicy", admitClusterFQDNNetworkPolicy(cfg))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	return mux
}

func admitFQDNNetworkPolicy(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		review, err := decodeReview(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var fp netv1alpha1.FQDNNetworkPolicy
		if err := json.Unmarshal(review.Request.Object.Raw, &fp); err != nil {
			respond(w, review.Request.UID, false, "failed to decode object: "+err.Error())
			return
		}
		if errs := validateEgressRules(fp.Spec.Egress, cfg.SnoopEnabled); len(errs) > 0 {
			respond(w, review.Request.UID, false, strings.Join(errs, "; "))
			return
		}
		respond(w, review.Request.UID, true, "")
	}
}

func admitClusterFQDNNetworkPolicy(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		review, err := decodeReview(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var cp netv1alpha1.ClusterFQDNNetworkPolicy
		if err := json.Unmarshal(review.Request.Object.Raw, &cp); err != nil {
			respond(w, review.Request.UID, false, "failed to decode object: "+err.Error())
			return
		}
		if errs := validateEgressRules(cp.Spec.Egress, cfg.SnoopEnabled); len(errs) > 0 {
			respond(w, review.Request.UID, false, strings.Join(errs, "; "))
			return
		}
		respond(w, review.Request.UID, true, "")
	}
}

// validateEgressRules returns human-readable errors for any invalid rule.
func validateEgressRules(rules []netv1alpha1.FQDNRule, snoopEnabled bool) []string {
	var errs []string
	seen := make(map[string]struct{})

	for i, rule := range rules {
		label := fmt.Sprintf("egress[%d](%q)", i, rule.Match)

		if rule.Match == "" {
			errs = append(errs, label+": match is required")
			continue
		}
		if strings.HasPrefix(rule.Match, "*.") && !snoopEnabled {
			errs = append(errs, label+": wildcards require the snoop resolver (--enable-snoop-resolver)")
		}
		if !fqdnRE.MatchString(rule.Match) {
			errs = append(errs, label+": not a valid FQDN or wildcard FQDN")
		}
		if net.ParseIP(rule.Match) != nil {
			errs = append(errs, label+": use NetworkPolicy ipBlock for raw IPs, not FQDNs")
		}
		if _, dup := seen[rule.Match]; dup {
			errs = append(errs, label+": duplicate match rule")
		}
		seen[rule.Match] = struct{}{}

		for j, p := range rule.Ports {
			pl := fmt.Sprintf("egress[%d].ports[%d]", i, j)
			if p.Port < 1 || p.Port > 65535 {
				errs = append(errs, pl+fmt.Sprintf(": port %d out of range 1–65535", p.Port))
			}
			switch p.Protocol {
			case "TCP", "UDP", "SCTP", "":
			default:
				errs = append(errs, pl+fmt.Sprintf(": unknown protocol %q", p.Protocol))
			}
		}
	}
	return errs
}

func decodeReview(r *http.Request) (*admissionv1.AdmissionReview, error) {
	if !strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		return nil, fmt.Errorf("expected Content-Type application/json")
	}
	var review admissionv1.AdmissionReview
	if err := json.NewDecoder(r.Body).Decode(&review); err != nil {
		return nil, fmt.Errorf("decode AdmissionReview: %w", err)
	}
	if review.Request == nil {
		return nil, fmt.Errorf("AdmissionReview.Request is nil")
	}
	return &review, nil
}

func respond(w http.ResponseWriter, uid types.UID, allowed bool, msg string) {
	resp := &admissionv1.AdmissionResponse{UID: uid, Allowed: allowed}
	if !allowed {
		resp.Result = &metav1.Status{Message: msg}
	}
	out := admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{APIVersion: "admission.k8s.io/v1", Kind: "AdmissionReview"},
		Response: resp,
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}
