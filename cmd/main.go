package main

import (
	"os"

	netv1alpha1 "github.com/yourorg/fqdn-network-policy/api/v1alpha1"
	"github.com/yourorg/fqdn-network-policy/internal/controller"
	"github.com/yourorg/fqdn-network-policy/internal/dns"

	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

var scheme = runtime.NewScheme()

func init() {
	_ = clientgoscheme.AddToScheme(scheme)
	_ = networkingv1.AddToScheme(scheme)
	_ = netv1alpha1.AddToScheme(scheme)
}

func main() {
	ctrl.SetLogger(zap.New(zap.UseDevMode(true)))

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme: scheme,
		// TODO: set Metrics/HealthProbe bind addresses, leader election
		// (leader election matters here: only one replica should be
		// issuing DNS resolutions and writing NetworkPolicy objects).
	})
	if err != nil {
		ctrl.Log.Error(err, "unable to start manager")
		os.Exit(1)
	}

	reconciler := &controller.FQDNNetworkPolicyReconciler{
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		Resolver: dns.NewActiveResolver(), // swap to dns.NewSnoopResolver() later
	}

	if err := reconciler.SetupWithManager(mgr); err != nil {
		ctrl.Log.Error(err, "unable to create controller", "controller", "FQDNNetworkPolicy")
		os.Exit(1)
	}

	ctrl.Log.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		ctrl.Log.Error(err, "problem running manager")
		os.Exit(1)
	}
}
