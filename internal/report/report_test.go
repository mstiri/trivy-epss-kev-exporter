package report

import "testing"

func ptrBool(b bool) *bool { return &b }

func TestWorkload_FromOperatorLabels(t *testing.T) {
	r := &VulnerabilityReport{
		Metadata: Metadata{
			Namespace: "litellm",
			Labels: map[string]string{
				LabelResourceNamespace: "litellm",
				LabelResourceName:      "litellm-85bb58cf94",
				LabelResourceKind:      "ReplicaSet",
				LabelContainerName:     "litellm",
			},
			// ownerReferences present but must be ignored when labels win.
			OwnerReferences: []OwnerReference{
				{Kind: "ShouldBeIgnored", Name: "ignored", Controller: ptrBool(true)},
			},
		},
	}
	got := r.Workload()
	want := Workload{Namespace: "litellm", Name: "litellm-85bb58cf94", Kind: "ReplicaSet", Container: "litellm"}
	if got != want {
		t.Errorf("Workload = %+v, want %+v", got, want)
	}
}

func TestWorkload_OwnerRefFallback(t *testing.T) {
	r := &VulnerabilityReport{
		Metadata: Metadata{
			Namespace: "ns1",
			// no operator labels at all
			OwnerReferences: []OwnerReference{
				{Kind: "Job", Name: "not-controller", Controller: ptrBool(false)},
				{Kind: "ReplicaSet", Name: "foo-abc123", Controller: ptrBool(true)},
			},
		},
	}
	got := r.Workload()
	if got.Namespace != "ns1" {
		t.Errorf("Namespace = %q, want ns1 (from metadata)", got.Namespace)
	}
	if got.Name != "foo-abc123" || got.Kind != "ReplicaSet" {
		t.Errorf("Name/Kind = %q/%q, want foo-abc123/ReplicaSet (controller owner)", got.Name, got.Kind)
	}
	if got.Container != "" {
		t.Errorf("Container = %q, want empty (no label, no owner-ref source)", got.Container)
	}
}

func TestWorkload_OwnerRefFirstWhenNoController(t *testing.T) {
	r := &VulnerabilityReport{
		Metadata: Metadata{
			OwnerReferences: []OwnerReference{
				{Kind: "ReplicaSet", Name: "first"},
				{Kind: "ReplicaSet", Name: "second"},
			},
		},
	}
	if got := r.Workload(); got.Name != "first" {
		t.Errorf("Name = %q, want first (fallback to first ref when none is controller)", got.Name)
	}
}

func TestWorkload_PartialLabelsFilledFromOwnerRef(t *testing.T) {
	// Name present via label, Kind missing → Kind comes from the controller owner.
	r := &VulnerabilityReport{
		Metadata: Metadata{
			Labels: map[string]string{
				LabelResourceName: "labelled-name",
			},
			OwnerReferences: []OwnerReference{
				{Kind: "StatefulSet", Name: "owner-name", Controller: ptrBool(true)},
			},
		},
	}
	got := r.Workload()
	if got.Name != "labelled-name" {
		t.Errorf("Name = %q, want labelled-name (label wins)", got.Name)
	}
	if got.Kind != "StatefulSet" {
		t.Errorf("Kind = %q, want StatefulSet (filled from owner ref)", got.Kind)
	}
}

func TestFromJSON(t *testing.T) {
	data := []byte(`{
		"metadata": {"namespace":"ns","uid":"u1","labels":{"trivy-operator.resource.name":"w"}},
		"report": {"vulnerabilities":[{"vulnerabilityID":"CVE-1","resource":"pkg","severity":"HIGH"}]}
	}`)
	r, err := FromJSON(data)
	if err != nil {
		t.Fatalf("FromJSON: %v", err)
	}
	if r.Metadata.UID != "u1" || len(r.Report.Vulnerabilities) != 1 {
		t.Errorf("decoded unexpectedly: %+v", r)
	}
	if v := r.Report.Vulnerabilities[0]; v.VulnerabilityID != "CVE-1" || v.Resource != "pkg" || v.Severity != "HIGH" {
		t.Errorf("vuln decoded wrong: %+v", v)
	}
}

func TestFromJSON_Invalid(t *testing.T) {
	if _, err := FromJSON([]byte("{not json")); err == nil {
		t.Error("expected error on malformed JSON")
	}
}
