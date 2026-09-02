package main

import (
	"context"
	"flag"
	"net/http"
	"os"
	"time"

	netv1alpha1 "github.com/kunaldevxxx/fqdn-network-policy/api/v1alpha1"
	"github.com/kunaldevxxx/fqdn-network-policy/internal/controller"
	idns "github.com/kunaldevxxx/fqdn-network-policy/internal/dns"
	_ "github.com/kunaldevxxx/fqdn-network-policy/internal/metrics"
	"github.com/kunaldevxxx/fqdn-network-policy/internal/webhook"

	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

var scheme = runtime.NewScheme()

func init() {
	_ = clientgoscheme.AddToScheme(scheme)
	_ = networkingv1.AddToScheme(scheme)
	_ = netv1alpha1.AddToScheme(scheme)
}

func main() {
	var (
		metricsAddr          string
		healthProbeAddr      string
		webhookAddr          string
		enableLeaderElection bool
		coreDNSAddr          string
		enableSnoop          bool
		snoopListenAddr      string
		snoopUpstream        string
		enableMultiResolver  bool
	)

	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080",
		"Prometheus metrics endpoint address.")
	flag.StringVar(&healthProbeAddr, "health-probe-bind-address", ":8081",
		"Health and readiness probe endpoint address.")
	flag.StringVar(&webhookAddr, "webhook-bind-address", ":9443",
		"Validating admission webhook endpoint address.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election for HA deployments (2+ replicas).")
	flag.StringVar(&coreDNSAddr, "coredns-address", "",
		"host:port of cluster CoreDNS (e.g. 10.96.0.10:53). Queries cluster DNS "+
			"instead of the node resolver to reduce geo-DNS divergence.")
	flag.BoolVar(&enableSnoop, "enable-snoop-resolver", false,
		"Start the DNS forwarding proxy. Configure CoreDNS to forward . to "+
			"--snoop-listen-address so the controller sees actual pod DNS responses.")
	flag.StringVar(&snoopListenAddr, "snoop-listen-address", "0.0.0.0:5353",
		"Address the SnoopResolver DNS proxy listens on.")
	flag.StringVar(&snoopUpstream, "snoop-upstream", "",
		"Upstream DNS address the SnoopResolver forwards to (defaults to CoreDNS address or system resolver).")
	flag.BoolVar(&enableMultiResolver, "enable-multi-resolver", true,
		"Query multiple public DNS resolvers and union results to reduce CDN IP divergence.")
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseDevMode(true)))

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme: scheme,
		Metrics: metricsserver.Options{
			BindAddress: metricsAddr,
		},
		HealthProbeBindAddress:  healthProbeAddr,
		LeaderElection:          enableLeaderElection,
		LeaderElectionID:        "fqdn-network-policy.netsec.kunal.dev",
		LeaderElectionNamespace: "kube-system",
	})
	if err != nil {
		ctrl.Log.Error(err, "unable to start manager")
		os.Exit(1)
	}

	ping := healthz.Checker(func(_ *http.Request) error { return nil })
	if err := mgr.AddHealthzCheck("healthz", ping); err != nil {
		ctrl.Log.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", ping); err != nil {
		ctrl.Log.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	// ── Resolver selection ─────────────────────────────────────────────────
	// Priority: SnoopResolver (best) > MultiResolver (good) > ActiveResolver (baseline)
	var resolver idns.Resolver

	if enableSnoop {
		upstream := snoopUpstream
		if upstream == "" {
			upstream = coreDNSAddr
		}
		sr := idns.NewSnoopResolver(snoopListenAddr, upstream)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if startErr := sr.Start(ctx); startErr != nil {
			ctrl.Log.Error(startErr, "snoop resolver failed to start, falling back to multi-resolver")
			resolver = idns.NewMultiResolver(extraUpstreams(coreDNSAddr))
		} else {
			ctrl.Log.Info("snoop resolver started",
				"listen", snoopListenAddr, "upstream", upstream)
			resolver = sr
		}
	} else if enableMultiResolver {
		ctrl.Log.Info("multi-resolver enabled (unions 4 public upstreams for CDN coverage)")
		resolver = idns.NewMultiResolver(extraUpstreams(coreDNSAddr))
	} else if coreDNSAddr != "" {
		ctrl.Log.Info("CoreDNS resolver", "address", coreDNSAddr)
		resolver = idns.NewCoreDNSResolver(coreDNSAddr)
	} else {
		resolver = idns.NewActiveResolver()
	}

	// ── FQDNNetworkPolicy controller ───────────────────────────────────────
	churnTracker := idns.NewChurnTracker()

	if err := (&controller.FQDNNetworkPolicyReconciler{
		Client:       mgr.GetClient(),
		Scheme:       mgr.GetScheme(),
		Resolver:     resolver,
		Recorder:     mgr.GetEventRecorderFor("fqdn-network-policy"), //nolint:staticcheck
		ChurnTracker: churnTracker,
	}).SetupWithManager(mgr); err != nil {
		ctrl.Log.Error(err, "unable to create controller", "controller", "FQDNNetworkPolicy")
		os.Exit(1)
	}

	// ── ClusterFQDNNetworkPolicy controller ────────────────────────────────
	if err := (&controller.ClusterFQDNNetworkPolicyReconciler{
		Client:       mgr.GetClient(),
		Scheme:       mgr.GetScheme(),
		Resolver:     resolver,
		Recorder:     mgr.GetEventRecorderFor("cluster-fqdn-network-policy"), //nolint:staticcheck
		ChurnTracker: churnTracker,
	}).SetupWithManager(mgr); err != nil {
		ctrl.Log.Error(err, "unable to create controller", "controller", "ClusterFQDNNetworkPolicy")
		os.Exit(1)
	}

	// ── Admission webhook ─────────────────────────────────────────────────
	whHandler := webhook.Handler(webhook.Config{SnoopEnabled: enableSnoop})
	whServer := &http.Server{
		Addr:         webhookAddr,
		Handler:      whHandler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
	go func() {
		ctrl.Log.Info("starting webhook server", "address", webhookAddr)
		// In production, provide TLS certs via --tls-cert-file and --tls-key-file.
		// For now, HTTP is used in-cluster behind a TLS terminator.
		if err := whServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			ctrl.Log.Error(err, "webhook server error")
		}
	}()

	ctrl.Log.Info("starting manager",
		"metrics", metricsAddr,
		"healthProbe", healthProbeAddr,
		"webhook", webhookAddr,
		"leaderElection", enableLeaderElection,
		"snoopEnabled", enableSnoop,
		"multiResolverEnabled", enableMultiResolver,
	)
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		ctrl.Log.Error(err, "problem running manager")
		os.Exit(1)
	}
}

// extraUpstreams returns a non-empty list of extra DNS upstreams if coreDNSAddr is set.
func extraUpstreams(coreDNSAddr string) []string {
	if coreDNSAddr == "" {
		return nil
	}
	return []string{coreDNSAddr}
}
