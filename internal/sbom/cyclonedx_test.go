package sbom

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/trung-dev/modelgate/internal/finding"
	"github.com/trung-dev/modelgate/internal/hf"
	"github.com/trung-dev/modelgate/internal/scan"
)

var fixedTime = time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)

const fixtureSHA = "rev01abcdef01abcdef01abcdef01abcdef01"

var lfsHash = strings.Repeat("c", 64)

func fixtureResult() *scan.Result {
	return &scan.Result{
		RepoType:      "model",
		RepoID:        "fixture/benign",
		Revision:      fixtureSHA,
		AnalyzedFiles: []string{"modeling_clean.py"},
		Trust:         scan.TrustAssessment{AutoMapCount: 1},
		Tree: []hf.TreeEntry{
			{Type: "file", Path: "modeling_clean.py", OID: "aaa111", Size: 120},
			{Type: "file", Path: "config.json", OID: "bbb222", Size: 55},
			{Type: "file", Path: "weights.safetensors", LFS: &hf.LFS{OID: lfsHash}, Size: 1 << 30},
			{Type: "directory", Path: "subdir", OID: "ddd444"},
		},
		Findings: []finding.Finding{
			{Rule: "MG-CMD-001", Severity: finding.SeverityCritical, Title: "Shell", Message: "observed", File: "modeling_clean.py", Remediation: "fix"},
			{Rule: "MG-TRUST-002", Severity: finding.SeverityMedium, Title: "auto_map", Message: "present", Remediation: "review"},
		},
	}
}

func TestBuildBOMStructure(t *testing.T) {
	t.Parallel()
	bom := Build(fixtureResult(), Options{ToolVersion: "1.0.0", Homepage: "https://example.invalid", Timestamp: fixedTime})

	if bom.BOMFormat != "CycloneDX" || bom.SpecVersion != SpecVersion {
		t.Fatalf("header = %s %s", bom.BOMFormat, bom.SpecVersion)
	}
	if !strings.HasPrefix(bom.SerialNumber, "urn:uuid:") || len(bom.SerialNumber) != len("urn:uuid:")+36 {
		t.Fatalf("serial = %q", bom.SerialNumber)
	}
	if bom.Version != 1 {
		t.Fatalf("version = %d", bom.Version)
	}
	if bom.Metadata.Timestamp != "2026-11-11T12:00:00Z" {
		t.Fatalf("timestamp = %q", bom.Metadata.Timestamp)
	}
	if len(bom.Metadata.Tools) != 1 || bom.Metadata.Tools[0].Name != "modelgate" {
		t.Fatalf("tools = %+v", bom.Metadata.Tools)
	}
	if bom.Metadata.Component.Type != "machine-learning-model" {
		t.Fatalf("component type = %q", bom.Metadata.Component.Type)
	}
	if bom.Metadata.Component.Name != "fixture/benign" || bom.Metadata.Component.Version != fixtureSHA {
		t.Fatalf("component = %+v", bom.Metadata.Component)
	}
}

func TestBuildComponentsAndHashes(t *testing.T) {
	t.Parallel()
	bom := Build(fixtureResult(), Options{Timestamp: fixedTime})

	// Directories are excluded; files are sorted by path.
	var names []string
	for _, c := range bom.Components {
		names = append(names, c.Name)
	}
	want := []string{"config.json", "modeling_clean.py", "weights.safetensors"}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Fatalf("components = %v", names)
	}

	byName := map[string]Component{}
	for _, c := range bom.Components {
		byName[c.Name] = c
	}
	if h := byName["config.json"].Hashes; len(h) != 1 || h[0].Alg != "SHA-1" {
		t.Fatalf("config hashes = %+v", h)
	}
	if h := byName["weights.safetensors"].Hashes; len(h) != 1 || h[0].Alg != "SHA-256" || h[0].Content != lfsHash {
		t.Fatalf("lfs hashes = %+v", h)
	}
	if role := propValue(byName["config.json"], "modelgate:role"); role != "model-config" {
		t.Fatalf("role = %q", role)
	}
	if analyzed := propValue(byName["modeling_clean.py"], "modelgate:analyzed"); analyzed != "true" {
		t.Fatalf("analyzed = %q", analyzed)
	}
	if analyzed := propValue(byName["weights.safetensors"], "modelgate:analyzed"); analyzed != "false" {
		t.Fatalf("weights analyzed = %q", analyzed)
	}
}

func TestBuildVulnerabilities(t *testing.T) {
	t.Parallel()
	bom := Build(fixtureResult(), Options{Timestamp: fixedTime})
	if len(bom.Vulnerabilities) != 2 {
		t.Fatalf("vulnerabilities = %+v", bom.Vulnerabilities)
	}
	v := bom.Vulnerabilities[0]
	if v.ID != "MG-CMD-001" {
		t.Fatalf("first vuln = %+v", v)
	}
	if v.Source.Name != "ModelGate static analysis" {
		t.Fatalf("source = %+v", v.Source)
	}
	if len(v.Ratings) != 1 || v.Ratings[0].Severity != "critical" || v.Ratings[0].Method != "other" {
		t.Fatalf("ratings = %+v", v.Ratings)
	}
	// modeling_clean.py exists as a component, so the affect points at it.
	if len(v.Affects) != 1 || !strings.HasPrefix(v.Affects[0].Ref, "file/modeling_clean.py@") {
		t.Fatalf("affects = %+v", v.Affects)
	}
	// The auto_map finding has no file, so it points at the model component.
	if got := bom.Vulnerabilities[1].Affects[0].Ref; !strings.HasPrefix(got, "model/") {
		t.Fatalf("affects = %q", got)
	}
}

func TestBuildDatasetComponentType(t *testing.T) {
	t.Parallel()
	res := fixtureResult()
	res.RepoType = "dataset"
	bom := Build(res, Options{Timestamp: fixedTime})
	if bom.Metadata.Component.Type != "file" {
		t.Fatalf("dataset component type = %q", bom.Metadata.Component.Type)
	}
}

func TestSerialNumberStable(t *testing.T) {
	t.Parallel()
	a := Build(fixtureResult(), Options{Timestamp: fixedTime})
	b := Build(fixtureResult(), Options{Timestamp: fixedTime})
	if a.SerialNumber != b.SerialNumber {
		t.Fatal("serial number must be deterministic for identical input")
	}
	other := fixtureResult()
	other.Revision = "other01234567890123456789012345678901234"
	c := Build(other, Options{Timestamp: fixedTime})
	if a.SerialNumber == c.SerialNumber {
		t.Fatal("different revision must yield different serial")
	}
}

func TestBOMJSON(t *testing.T) {
	t.Parallel()
	bom := Build(fixtureResult(), Options{ToolVersion: "1.0.0", Timestamp: fixedTime})
	data, err := bom.JSON()
	if err != nil {
		t.Fatalf("json: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if decoded["bomFormat"] != "CycloneDX" {
		t.Fatalf("decoded = %v", decoded)
	}
	if !strings.HasSuffix(string(data), "\n") {
		t.Fatal("sbom must end with newline")
	}
}

func TestBuildEmptyTree(t *testing.T) {
	t.Parallel()
	res := &scan.Result{RepoID: "fixture/empty", RepoType: "model", Revision: fixtureSHA}
	bom := Build(res, Options{Timestamp: fixedTime})
	if bom.Components == nil || len(bom.Components) != 0 {
		t.Fatalf("components = %v", bom.Components)
	}
	data, err := bom.JSON()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"components": []`) {
		t.Fatal("empty components must serialize as []")
	}
}

func TestFileRole(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"config.json":    "model-config",
		"a.py":           "python-source",
		"sub/b.py":       "python-source",
		"README.md":      "documentation",
		"tokenizer.json": "metadata",
		"weights.bin":    "other",
	}
	for path, want := range cases {
		if got := fileRole(path); got != want {
			t.Fatalf("fileRole(%q) = %q, want %q", path, got, want)
		}
	}
}

func propValue(c Component, name string) string {
	for _, p := range c.Properties {
		if p.Name == name {
			return p.Value
		}
	}
	return ""
}
