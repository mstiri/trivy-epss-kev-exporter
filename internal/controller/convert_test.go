package controller

import (
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestReportFromUnstructured(t *testing.T) {
	u := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "aquasecurity.github.io/v1alpha1",
		"kind":       "VulnerabilityReport",
		"metadata": map[string]any{
			"name":      "replicaset-litellm-85bb58cf94-litellm",
			"namespace": "litellm",
			"uid":       "uid-1",
			"labels": map[string]any{
				"trivy-operator.resource.kind":  "ReplicaSet",
				"trivy-operator.resource.name":  "litellm-85bb58cf94",
				"trivy-operator.container.name": "litellm",
			},
		},
		"report": map[string]any{
			"vulnerabilities": []any{
				map[string]any{"vulnerabilityID": "CVE-2021-44228", "resource": "log4j", "severity": "CRITICAL"},
			},
		},
	}}

	rep, err := reportFromUnstructured(u)
	if err != nil {
		t.Fatalf("reportFromUnstructured: %v", err)
	}
	if rep.Metadata.UID != "uid-1" || rep.Metadata.Name != "replicaset-litellm-85bb58cf94-litellm" {
		t.Errorf("metadata decoded wrong: %+v", rep.Metadata)
	}
	if len(rep.Report.Vulnerabilities) != 1 || rep.Report.Vulnerabilities[0].VulnerabilityID != "CVE-2021-44228" {
		t.Errorf("vulnerabilities decoded wrong: %+v", rep.Report.Vulnerabilities)
	}
	w := rep.Workload()
	if w.Name != "litellm-85bb58cf94" || w.Kind != "ReplicaSet" || w.Container != "litellm" {
		t.Errorf("workload resolved wrong: %+v", w)
	}
}

func TestReportFromUnstructured_Nil(t *testing.T) {
	if _, err := reportFromUnstructured(nil); err == nil {
		t.Error("expected error for nil unstructured")
	}
}
