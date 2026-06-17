package controller

import (
	"strings"

	appsv1 "k8s.io/api/apps/v1"

	"github.com/mstiri/trivy-epss-kev-exporter/internal/report"
)

// Resolver maps a report's base workload (from the operator labels) to the
// workload we actually label series with.
type Resolver interface {
	Resolve(w report.Workload) report.Workload
}

// identityResolver returns the workload unchanged. Used when roll-up is disabled
// and as the default in unit tests of the pure layers.
type identityResolver struct{}

func (identityResolver) Resolve(w report.Workload) report.Workload { return w }

// rsGetter fetches a ReplicaSet by namespace/name. In production it is the
// ReplicaSet lister's Get; in tests it is a stub, so the roll-up logic is
// testable without a running informer.
type rsGetter func(namespace, name string) (*appsv1.ReplicaSet, error)

// replicaSetResolver rolls a ReplicaSet workload up to its owning Deployment so
// the `workload` label is the stable Deployment name rather than a per-rollout
// ReplicaSet hash. Anything it cannot resolve (not a ReplicaSet, lister miss, no
// Deployment owner) passes through unchanged — we never fail enrichment over it.
type replicaSetResolver struct {
	get rsGetter
}

func (r replicaSetResolver) Resolve(w report.Workload) report.Workload {
	if w.Name == "" || !strings.EqualFold(w.Kind, "ReplicaSet") {
		return w
	}
	rs, err := r.get(w.Namespace, w.Name)
	if err != nil || rs == nil {
		return w
	}
	for _, o := range rs.OwnerReferences {
		if o.Controller != nil && *o.Controller && o.Kind == "Deployment" {
			w.Name = o.Name
			w.Kind = "Deployment"
			return w
		}
	}
	return w
}
