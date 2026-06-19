// Package report holds a MINIMAL local view of the Trivy Operator
// VulnerabilityReport CRD — only the fields this read-only exporter consumes.
//
// We deliberately do NOT import the upstream aquasecurity/trivy-operator API
// types: the exporter reads a handful of fields, so a lean local struct keeps
// the dependency tree small and matches the read-only spirit. The informer
// (step 5) decodes the watched objects into this struct.
//
// GVK: aquasecurity.github.io/v1alpha1, VulnerabilityReport.
package report

import (
	"encoding/json"
	"strings"
)

// Operator labels that carry the scanned workload's identity. Trivy Operator
// stamps these onto every VulnerabilityReport; they are the authoritative
// source for workload attribution (ownerReferences is only a fallback).
const (
	LabelResourceKind      = "trivy-operator.resource.kind"
	LabelResourceName      = "trivy-operator.resource.name"
	LabelResourceNamespace = "trivy-operator.resource.namespace"
	LabelContainerName     = "trivy-operator.container.name"
)

// VulnerabilityReport is the trimmed CRD: just metadata + report.vulnerabilities.
type VulnerabilityReport struct {
	Metadata Metadata `json:"metadata"`
	Report   Spec     `json:"report"`
}

// Metadata is the trimmed object metadata.
type Metadata struct {
	Name            string            `json:"name"`
	Namespace       string            `json:"namespace"`
	UID             string            `json:"uid"`
	Labels          map[string]string `json:"labels"`
	OwnerReferences []OwnerReference  `json:"ownerReferences"`
}

// OwnerReference is the trimmed owner reference (fallback workload source).
type OwnerReference struct {
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	Controller *bool  `json:"controller"`
}

// Spec is the trimmed `report` block.
type Spec struct {
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

// Vulnerability is the trimmed per-CVE entry. severity is taken verbatim from
// the CRD (NOT re-derived from the CVSS score, per the metric contract).
type Vulnerability struct {
	VulnerabilityID string `json:"vulnerabilityID"`
	Resource        string `json:"resource"`
	Severity        string `json:"severity"`
}

// Workload is the resolved owner workload a report's CVEs are attributed to.
type Workload struct {
	Namespace string
	Name      string
	Kind      string
	Container string
}

// Workload resolves the owning workload for the report. It prefers the operator
// labels (authoritative) and falls back to ownerReferences / object metadata for
// any piece the labels don't provide.
//
// NOTE: the operator labels point at the IMMEDIATELY scanned resource — for a
// Deployment that is the ReplicaSet (e.g. kind=ReplicaSet, name=foo-85bb58cf94).
// We do not roll ReplicaSet up to its Deployment here: that needs a cluster read
// (a ReplicaSet lister) and is a step-5 concern. See CLAUDE.md — the per-rollout
// ReplicaSet-name churn is a known cardinality tradeoff to settle before then.
func (r *VulnerabilityReport) Workload() Workload {
	l := r.Metadata.Labels
	w := Workload{
		Namespace: firstNonEmpty(l[LabelResourceNamespace], r.Metadata.Namespace),
		Name:      l[LabelResourceName],
		Kind:      l[LabelResourceKind],
		Container: l[LabelContainerName],
	}
	if w.Name == "" || w.Kind == "" {
		if o, ok := r.controllerOwner(); ok {
			if w.Name == "" {
				w.Name = o.Name
			}
			if w.Kind == "" {
				w.Kind = o.Kind
			}
		}
	}
	return w
}

// controllerOwner returns the controlling ownerReference (controller: true),
// falling back to the first reference if none is explicitly the controller.
func (r *VulnerabilityReport) controllerOwner() (OwnerReference, bool) {
	refs := r.Metadata.OwnerReferences
	for _, o := range refs {
		if o.Controller != nil && *o.Controller {
			return o, true
		}
	}
	if len(refs) > 0 {
		return refs[0], true
	}
	return OwnerReference{}, false
}

// FromJSON decodes a VulnerabilityReport from its JSON encoding. The informer
// path (step 5) will reuse this after converting the watched object to JSON, or
// decode directly into the struct.
func FromJSON(data []byte) (*VulnerabilityReport, error) {
	var r VulnerabilityReport
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
