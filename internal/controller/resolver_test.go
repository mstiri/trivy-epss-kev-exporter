package controller

import (
	"errors"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/mstiri/trivy-epss-kev-exporter/internal/report"
)

func ptrBool(b bool) *bool { return &b }

func rsWithOwner(owner metav1.OwnerReference) *appsv1.ReplicaSet {
	return &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{OwnerReferences: []metav1.OwnerReference{owner}}}
}

func TestReplicaSetResolver_RollsUpToDeployment(t *testing.T) {
	r := replicaSetResolver{get: func(ns, name string) (*appsv1.ReplicaSet, error) {
		if ns != "litellm" || name != "litellm-85bb58cf94" {
			t.Errorf("unexpected lookup %s/%s", ns, name)
		}
		return rsWithOwner(metav1.OwnerReference{Kind: "Deployment", Name: "litellm", Controller: ptrBool(true)}), nil
	}}
	in := report.Workload{Namespace: "litellm", Name: "litellm-85bb58cf94", Kind: "ReplicaSet", Container: "litellm"}
	got := r.Resolve(in)
	if got.Name != "litellm" || got.Kind != "Deployment" {
		t.Errorf("Resolve = %s/%s, want litellm/Deployment", got.Name, got.Kind)
	}
	if got.Namespace != "litellm" || got.Container != "litellm" {
		t.Errorf("Resolve clobbered namespace/container: %+v", got)
	}
}

func TestReplicaSetResolver_Passthroughs(t *testing.T) {
	rs := rsWithOwner(metav1.OwnerReference{Kind: "Deployment", Name: "dep", Controller: ptrBool(true)})

	tests := map[string]struct {
		in  report.Workload
		get rsGetter
	}{
		"non-ReplicaSet kind untouched": {
			in:  report.Workload{Name: "foo", Kind: "DaemonSet"},
			get: func(string, string) (*appsv1.ReplicaSet, error) { return rs, nil },
		},
		"empty name untouched": {
			in:  report.Workload{Kind: "ReplicaSet"},
			get: func(string, string) (*appsv1.ReplicaSet, error) { return rs, nil },
		},
		"lister miss keeps ReplicaSet identity": {
			in:  report.Workload{Name: "rs-1", Kind: "ReplicaSet"},
			get: func(string, string) (*appsv1.ReplicaSet, error) { return nil, errors.New("not found") },
		},
		"no Deployment owner keeps ReplicaSet identity": {
			in:  report.Workload{Name: "rs-1", Kind: "ReplicaSet"},
			get: func(string, string) (*appsv1.ReplicaSet, error) { return &appsv1.ReplicaSet{}, nil },
		},
		"non-controller Deployment owner ignored": {
			in: report.Workload{Name: "rs-1", Kind: "ReplicaSet"},
			get: func(string, string) (*appsv1.ReplicaSet, error) {
				return rsWithOwner(metav1.OwnerReference{Kind: "Deployment", Name: "dep", Controller: ptrBool(false)}), nil
			},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got := replicaSetResolver{get: tt.get}.Resolve(tt.in)
			if got != tt.in {
				t.Errorf("Resolve(%+v) = %+v, want unchanged", tt.in, got)
			}
		})
	}
}

func TestIdentityResolver(t *testing.T) {
	in := report.Workload{Name: "x", Kind: "ReplicaSet"}
	if got := (identityResolver{}).Resolve(in); got != in {
		t.Errorf("identity changed workload: %+v", got)
	}
}
