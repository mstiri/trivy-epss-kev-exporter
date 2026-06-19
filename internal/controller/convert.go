package controller

import (
	"fmt"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/mstiri/trivy-epss-kev-exporter/internal/report"
)

// reportFromUnstructured converts a watched dynamic object into our trimmed
// VulnerabilityReport. It round-trips through JSON (the object's native form)
// and reuses report.FromJSON, so the field mapping lives in exactly one place.
func reportFromUnstructured(u *unstructured.Unstructured) (*report.VulnerabilityReport, error) {
	if u == nil {
		return nil, fmt.Errorf("controller: nil unstructured object")
	}
	data, err := u.MarshalJSON()
	if err != nil {
		return nil, fmt.Errorf("controller: marshal unstructured: %w", err)
	}
	return report.FromJSON(data)
}
