// Package controller is the Kubernetes-facing layer: it watches
// VulnerabilityReport CRDs with a client-go SharedInformer, resolves workload
// ownership (incl. ReplicaSet→Deployment roll-up), and funnels every change
// through a single rate-limited workqueue to a reconcile callback.
//
// What the informer machinery abstracts (for future readers):
//   - LIST-then-WATCH: on start the informer LISTs all VulnerabilityReports to
//     prime an in-memory cache (the indexer/store), then WATCHes for deltas.
//   - The cache/store: a thread-safe local mirror of cluster state; the lister
//     and our process() read from it instead of hitting the API server.
//   - Event handlers: OnAdd/OnUpdate/OnDelete fire as deltas arrive; we use them
//     only to ENQUEUE keys — all real work happens in the workqueue worker so it
//     is serialized per key and deduplicated.
//   - Resync: a periodic re-delivery of every cached object as an OnUpdate. Off
//     by default here (feed changes, not resync, drive re-enrichment — see
//     CLAUDE.md); a non-zero interval only adds cheap self-healing.
package controller

import (
	"fmt"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// BuildConfig returns a REST config. With kubeconfig set it loads that file;
// otherwise it tries in-cluster config and finally falls back to the default
// kubeconfig loading rules (KUBECONFIG / ~/.kube/config) for local/dev runs.
func BuildConfig(kubeconfig string) (*rest.Config, error) {
	if kubeconfig != "" {
		return clientcmd.BuildConfigFromFlags("", kubeconfig)
	}
	if cfg, err := rest.InClusterConfig(); err == nil {
		return cfg, nil
	}
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, &clientcmd.ConfigOverrides{}).ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("controller: no in-cluster or kubeconfig config available: %w", err)
	}
	return cfg, nil
}

// Clients bundles the typed and dynamic clients the controller needs.
type Clients struct {
	// Dynamic reads the VulnerabilityReport CRD without generated typed code.
	Dynamic dynamic.Interface
	// Kube is the typed client, used only for the ReplicaSet lister behind
	// roll-up (nil-capable: roll-up may be disabled).
	Kube kubernetes.Interface
}

// NewClients builds both clients from a REST config.
func NewClients(cfg *rest.Config) (*Clients, error) {
	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("controller: dynamic client: %w", err)
	}
	kube, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("controller: kube client: %w", err)
	}
	return &Clients{Dynamic: dyn, Kube: kube}, nil
}
