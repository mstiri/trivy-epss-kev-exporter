package controller

import (
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	kubefake "k8s.io/client-go/kubernetes/fake"

	"github.com/mstiri/trivy-epss-kev-exporter/internal/report"
)

type capture struct {
	key    string
	rep    *report.VulnerabilityReport
	w      report.Workload
	exists bool
	calls  int
}

func newTestController(t *testing.T, opts Options, rec ReconcileFunc) *Controller {
	t.Helper()
	scheme := runtime.NewScheme()
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme,
		map[schema.GroupVersionResource]string{vrGVR: "VulnerabilityReportList"})
	kube := kubefake.NewSimpleClientset()
	c, err := New(&Clients{Dynamic: dyn, Kube: kube}, rec, nil, opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func vrObject(ns, name, rsName string, vulns ...map[string]any) *unstructured.Unstructured {
	vs := make([]any, len(vulns))
	for i, v := range vulns {
		vs[i] = v
	}
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "aquasecurity.github.io/v1alpha1",
		"kind":       "VulnerabilityReport",
		"metadata": map[string]any{
			"name":      name,
			"namespace": ns,
			"uid":       "uid-" + name,
			"labels": map[string]any{
				"trivy-operator.resource.kind":      "ReplicaSet",
				"trivy-operator.resource.name":      rsName,
				"trivy-operator.resource.namespace": ns,
				"trivy-operator.container.name":     "litellm",
			},
		},
		"report": map[string]any{"vulnerabilities": vs},
	}}
}

var log4j = map[string]any{"vulnerabilityID": "CVE-2021-44228", "resource": "log4j", "severity": "CRITICAL"}

func TestNew_RequiresReconcile(t *testing.T) {
	if _, err := New(&Clients{}, nil, nil, Options{}); err == nil {
		t.Error("New with nil reconcile should error")
	}
}

func TestProcess_ExistingReport(t *testing.T) {
	var got capture
	c := newTestController(t, Options{}, func(key string, rep *report.VulnerabilityReport, w report.Workload, exists bool) error {
		got = capture{key, rep, w, exists, got.calls + 1}
		return nil
	})
	if err := c.vrInformer.GetIndexer().Add(vrObject("litellm", "rep1", "litellm-85bb58cf94", log4j)); err != nil {
		t.Fatalf("indexer add: %v", err)
	}

	if err := c.process("litellm/rep1"); err != nil {
		t.Fatalf("process: %v", err)
	}
	if !got.exists || got.key != "litellm/rep1" {
		t.Errorf("got key=%q exists=%v, want litellm/rep1 true", got.key, got.exists)
	}
	if got.rep == nil || len(got.rep.Report.Vulnerabilities) != 1 {
		t.Fatalf("rep not decoded: %+v", got.rep)
	}
	// Roll-up disabled → workload keeps the ReplicaSet identity from the labels.
	if got.w.Kind != "ReplicaSet" || got.w.Name != "litellm-85bb58cf94" || got.w.Namespace != "litellm" {
		t.Errorf("workload = %+v, want ReplicaSet/litellm-85bb58cf94/litellm", got.w)
	}
}

func TestProcess_MissingReportSignalsDelete(t *testing.T) {
	var got capture
	c := newTestController(t, Options{}, func(key string, rep *report.VulnerabilityReport, w report.Workload, exists bool) error {
		got = capture{key, rep, w, exists, got.calls + 1}
		return nil
	})
	if err := c.process("litellm/ghost"); err != nil {
		t.Fatalf("process: %v", err)
	}
	if got.exists || got.rep != nil || got.key != "litellm/ghost" {
		t.Errorf("got %+v, want key=litellm/ghost exists=false rep=nil", got)
	}
}

func TestProcess_WithRollup(t *testing.T) {
	var got capture
	c := newTestController(t, Options{EnableRollup: true}, func(key string, rep *report.VulnerabilityReport, w report.Workload, exists bool) error {
		got = capture{key, rep, w, exists, got.calls + 1}
		return nil
	})
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{
		Name:      "litellm-85bb58cf94",
		Namespace: "litellm",
		OwnerReferences: []metav1.OwnerReference{
			{Kind: "Deployment", Name: "litellm", Controller: ptrBool(true)},
		},
	}}
	if err := c.rsInformer.GetIndexer().Add(rs); err != nil {
		t.Fatalf("rs indexer add: %v", err)
	}
	if err := c.vrInformer.GetIndexer().Add(vrObject("litellm", "rep1", "litellm-85bb58cf94", log4j)); err != nil {
		t.Fatalf("vr indexer add: %v", err)
	}

	if err := c.process("litellm/rep1"); err != nil {
		t.Fatalf("process: %v", err)
	}
	if got.w.Kind != "Deployment" || got.w.Name != "litellm" {
		t.Errorf("rolled-up workload = %s/%s, want Deployment/litellm", got.w.Kind, got.w.Name)
	}
}

func TestEnqueue_NamespaceAllowlist(t *testing.T) {
	c := newTestController(t, Options{Namespaces: []string{"allowed"}}, noopReconcile)

	c.enqueue(vrObject("denied", "r", "rs"))
	if c.queue.Len() != 0 {
		t.Errorf("denied namespace enqueued: queue len %d, want 0", c.queue.Len())
	}
	c.enqueue(vrObject("allowed", "r", "rs"))
	if c.queue.Len() != 1 {
		t.Errorf("allowed namespace not enqueued: queue len %d, want 1", c.queue.Len())
	}
}

func TestEnqueue_AllNamespacesWhenNoAllowlist(t *testing.T) {
	c := newTestController(t, Options{}, noopReconcile)
	c.enqueue(vrObject("any", "r", "rs"))
	if c.queue.Len() != 1 {
		t.Errorf("queue len %d, want 1 (empty allowlist = all namespaces)", c.queue.Len())
	}
}

func noopReconcile(string, *report.VulnerabilityReport, report.Workload, bool) error { return nil }

func TestEnqueueAll_SweepsInScopeKeys(t *testing.T) {
	c := newTestController(t, Options{Namespaces: []string{"a"}}, noopReconcile)
	for _, o := range []*unstructured.Unstructured{
		vrObject("a", "r1", "rs"),
		vrObject("b", "r2", "rs"), // out of allowlist
		vrObject("a", "r3", "rs"),
	} {
		if err := c.vrInformer.GetIndexer().Add(o); err != nil {
			t.Fatalf("indexer add: %v", err)
		}
	}

	c.EnqueueAll()
	if c.queue.Len() != 2 {
		t.Errorf("EnqueueAll queued %d keys, want 2 (only namespace a)", c.queue.Len())
	}
}

func TestEnqueueAll_AllNamespaces(t *testing.T) {
	c := newTestController(t, Options{}, noopReconcile)
	if err := c.vrInformer.GetIndexer().Add(vrObject("a", "r1", "rs")); err != nil {
		t.Fatalf("indexer add: %v", err)
	}
	if err := c.vrInformer.GetIndexer().Add(vrObject("b", "r2", "rs")); err != nil {
		t.Fatalf("indexer add: %v", err)
	}
	c.EnqueueAll()
	if c.queue.Len() != 2 {
		t.Errorf("EnqueueAll queued %d keys, want 2", c.queue.Len())
	}
}
