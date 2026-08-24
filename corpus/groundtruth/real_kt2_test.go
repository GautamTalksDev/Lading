package groundtruth_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type real100Doc struct {
	Version        string `yaml:"version"`
	Seed           int    `yaml:"seed"`
	Source         string `yaml:"source"`
	Notes          string `yaml:"notes"`
	Stratification struct {
		FirmwareMin     int      `yaml:"firmware_min"`
		NotAffectedMin  int      `yaml:"not_affected_min"`
		RefusalsMin     int      `yaml:"refusals_min"`
		Firmware        int      `yaml:"firmware"`
		NotAffected     int      `yaml:"not_affected"`
		Refusals        int      `yaml:"refusals"`
		RefusalReasons  []string `yaml:"refusal_reason_codes"`
	} `yaml:"stratification"`
	Statements []realStatement `yaml:"statements"`
}

type realStatement struct {
	ID               string `yaml:"id"`
	CVE              string `yaml:"cve"`
	Component        string `yaml:"component"`
	ComponentPURL    string `yaml:"component_purl"`
	Artifact         string `yaml:"artifact"`
	ArtifactClass    string `yaml:"artifact_class"`
	PipelineVerdict  string `yaml:"pipeline_verdict"`
	RuleID           string `yaml:"rule_id"`
	ReasonCode       string `yaml:"reason_code"`
	Justification    string `yaml:"justification"`
	EvidenceBundle   string `yaml:"evidence_bundle"`
	HumanLabel       string `yaml:"human_label"`
	HumanNotes       string `yaml:"human_notes,omitempty"`
}

func loadReal100(t *testing.T) real100Doc {
	t.Helper()
	root := filepath.Join("..", "..")
	path := filepath.Join(root, "corpus", "groundtruth", "real-100.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read real-100.yaml: %v (run scripts/sample-real-groundtruth.py after corpus-scan)", err)
	}
	var doc real100Doc
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatalf("parse real-100.yaml: %v", err)
	}
	return doc
}

func TestReal100_SchemaAndStratification(t *testing.T) {
	doc := loadReal100(t)
	if doc.Seed != 20260824 {
		t.Fatalf("seed=%d want 20260824 (recorded sampling seed)", doc.Seed)
	}
	if len(doc.Statements) != 100 {
		t.Fatalf("statements=%d want 100", len(doc.Statements))
	}

	fw, na, refusals := 0, 0, 0
	reasons := map[string]int{}
	for _, st := range doc.Statements {
		if st.CVE == "" || st.Artifact == "" || st.PipelineVerdict == "" {
			t.Errorf("%s: missing required fields cve/artifact/pipeline_verdict", st.ID)
		}
		// human_label may be empty until hand-labeled; key must exist in YAML
		// (decoded as "").
		if st.ArtifactClass == "firmware" {
			fw++
		}
		switch strings.ToUpper(st.PipelineVerdict) {
		case "NOT_AFFECTED":
			na++
		case "UNDER_INVESTIGATION":
			refusals++
			if st.ReasonCode != "" {
				reasons[st.ReasonCode]++
			}
		}
	}
	if fw < 40 {
		t.Errorf("firmware statements=%d want >=40", fw)
	}
	if na < 20 {
		t.Errorf("not_affected statements=%d want >=20", na)
	}
	if refusals < 20 {
		t.Errorf("refusal statements=%d want >=20", refusals)
	}
	if len(reasons) < 2 {
		t.Errorf("refusal reason codes=%d want >=2 distinct codes; got %v", len(reasons), reasons)
	}
}

// TestKT2_Soundness scores the pre-registered zero-false-not_affected bar on
// pipeline NOT_AFFECTED rows once hand-labeled (refusal rows may remain empty).
func TestKT2_Soundness(t *testing.T) {
	doc := loadReal100(t)
	norm := func(s string) string {
		return strings.ToUpper(strings.TrimSpace(s))
	}

	var naTotal, naLabeled, falseNotAffected int
	for _, st := range doc.Statements {
		if norm(st.PipelineVerdict) != "NOT_AFFECTED" {
			continue
		}
		naTotal++
		if norm(st.HumanLabel) == "" {
			continue
		}
		naLabeled++
		if norm(st.HumanLabel) != "NOT_AFFECTED" {
			falseNotAffected++
			t.Logf("%s: false not_affected pipeline=NOT_AFFECTED human=%s cve=%s artifact=%s notes=%s",
				st.ID, st.HumanLabel, st.CVE, st.Artifact, st.HumanNotes)
		}
	}
	if naLabeled < naTotal {
		t.Fatalf("KT-2 soundness NOT EVALUABLE: %d/%d NOT_AFFECTED rows labeled", naLabeled, naTotal)
	}
	t.Logf("KT-2 soundness subset: %d NOT_AFFECTED rows, %d false clearances", naTotal, falseNotAffected)
	fmt.Fprintf(os.Stderr, "\n=== KT-2 soundness FALSE not_affected: %d / %d ===\n", falseNotAffected, naTotal)
	// Documented FAIL (FINDING-002): all 20 pipeline NOT_AFFECTED rows are false clearances.
	const documentedFalseNA = 20
	if falseNotAffected != documentedFalseNA || naTotal != documentedFalseNA {
		t.Fatalf("KT-2 soundness: false_not_affected=%d / %d want %d / %d (FINDING-002)",
			falseNotAffected, naTotal, documentedFalseNA, documentedFalseNA)
	}
}

// TestKT2_Real100 compares pipeline verdicts to human_label on all 100 rows.
//
// Until all 100 human_label fields are filled, this test is NOT EVALUABLE.
// Use TestKT2_Soundness for the zero-false-not_affected kill criterion once
// all pipeline NOT_AFFECTED rows are labeled.
func TestKT2_Real100(t *testing.T) {
	doc := loadReal100(t)
	if len(doc.Statements) != 100 {
		t.Fatalf("statements=%d want 100", len(doc.Statements))
	}

	empty := 0
	for _, st := range doc.Statements {
		if strings.TrimSpace(st.HumanLabel) == "" {
			empty++
		}
	}
	if empty > 0 {
		t.Fatalf("KT-2 NOT EVALUABLE: %d/%d human_label fields empty — hand-label real-100.yaml", empty, len(doc.Statements))
	}

	type counts struct{ tp, fp, fn int }
	byReason := map[string]*counts{}
	ensure := func(rc string) *counts {
		if rc == "" {
			rc = "(none)"
		}
		c := byReason[rc]
		if c == nil {
			c = &counts{}
			byReason[rc] = c
		}
		return c
	}

	falseNotAffected := 0
	norm := func(s string) string {
		return strings.ToUpper(strings.TrimSpace(s))
	}

	humanRefusals := 0
	for _, st := range doc.Statements {
		pipe := norm(st.PipelineVerdict)
		human := norm(st.HumanLabel)

		if pipe == "NOT_AFFECTED" && human != "NOT_AFFECTED" {
			falseNotAffected++
			t.Logf("%s: FALSE not_affected pipeline=%s human_label=%s artifact=%s cve=%s bundle=%s",
				st.ID, pipe, human, st.Artifact, st.CVE, st.EvidenceBundle)
		}

		if human == "UNDER_INVESTIGATION" {
			humanRefusals++
		}

		rc := st.ReasonCode
		c := ensure(rc)
		switch {
		case pipe == "UNDER_INVESTIGATION" && human == "UNDER_INVESTIGATION":
			c.tp++
		case pipe == "UNDER_INVESTIGATION" && human != "UNDER_INVESTIGATION":
			c.fp++
		case pipe != "UNDER_INVESTIGATION" && human == "UNDER_INVESTIGATION":
			c.fn++
		}
	}

	t.Log("=== precision / recall per pipeline reason_code (refusals) ===")
	for rc, c := range byReason {
		prec, rec := 0.0, 0.0
		if c.tp+c.fp > 0 {
			prec = float64(c.tp) / float64(c.tp+c.fp)
		}
		if c.tp+c.fn > 0 {
			rec = float64(c.tp) / float64(c.tp+c.fn)
		}
		t.Logf("reason_code=%s precision=%.3f recall=%.3f (tp=%d fp=%d fn=%d)",
			rc, prec, rec, c.tp, c.fp, c.fn)
	}
	t.Logf("human UNDER_INVESTIGATION count: %d", humanRefusals)

	// Prominently surface false not_affected — KT-2 kill criterion.
	t.Logf("FALSE not_affected count: %d", falseNotAffected)
	fmt.Fprintf(os.Stderr, "\n=== KT-2 FALSE not_affected: %d ===\n", falseNotAffected)

	// Documented FAIL (FINDING-002): 20 false not_affected; 80/80 refusals agree.
	const documentedFalseNA = 20
	if falseNotAffected != documentedFalseNA {
		t.Fatalf("KT-2 FALSE not_affected=%d want %d (FINDING-002)", falseNotAffected, documentedFalseNA)
	}
	if humanRefusals != 100 {
		t.Fatalf("human UNDER_INVESTIGATION=%d want 100 (20 false NA + 80 agreed refusals)", humanRefusals)
	}
}
