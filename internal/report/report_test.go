package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/trung-dev/modelgate/internal/finding"
	"github.com/trung-dev/modelgate/internal/pin"
	"github.com/trung-dev/modelgate/internal/scan"
)

var fixedTime = time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)

const fixtureSHA = "rev01abcdef01abcdef01abcdef01abcdef01"

func fixtureResult(findings ...finding.Finding) *scan.Result {
	return &scan.Result{
		RepoType:      "model",
		RepoID:        "fixture/benign",
		Revision:      fixtureSHA,
		AnalyzedFiles: []string{"modeling_clean.py"},
		Findings:      findings,
	}
}

func build(t *testing.T, res *scan.Result, failOn finding.Severity) *Report {
	t.Helper()
	rep, err := Build(res, BuildOptions{
		ToolVersion: "1.0.0",
		Now:         fixedTime,
		FailOn:      failOn,
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	return rep
}

func TestBuildSummaryAndExitCodes(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		findings []finding.Finding
		failOn   finding.Severity
		exit     int
		worst    string
		counts   func(Summary) bool
	}{
		{
			name:   "clean",
			failOn: finding.SeverityHigh,
			exit:   ExitOK, worst: "none",
			counts: func(s Summary) bool { return s.Info+s.Low+s.Medium+s.High+s.Critical == 0 },
		},
		{
			name: "medium below default fail-on passes",
			findings: []finding.Finding{
				{Rule: "R", Severity: finding.SeverityMedium, Title: "t", Remediation: "fix"},
			},
			failOn: finding.SeverityHigh,
			exit:   ExitOK, worst: "medium",
			counts: func(s Summary) bool { return s.Medium == 1 },
		},
		{
			name: "high fails default",
			findings: []finding.Finding{
				{Rule: "R", Severity: finding.SeverityHigh, Title: "t", Remediation: "fix"},
			},
			failOn: finding.SeverityHigh,
			exit:   ExitFindings, worst: "high",
			counts: func(s Summary) bool { return s.High == 1 },
		},
		{
			name: "critical fails info-level gate too",
			findings: []finding.Finding{
				{Rule: "R1", Severity: finding.SeverityInfo, Title: "t", Remediation: "fix"},
				{Rule: "R2", Severity: finding.SeverityCritical, Title: "t", Remediation: "fix"},
				{Rule: "R3", Severity: finding.SeverityLow, Title: "t", Remediation: "fix"},
			},
			failOn: finding.SeverityInfo,
			exit:   ExitFindings, worst: "critical",
			counts: func(s Summary) bool { return s.Info == 1 && s.Low == 1 && s.Critical == 1 },
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rep := build(t, fixtureResult(tc.findings...), tc.failOn)
			if rep.Summary.ExitCode != tc.exit {
				t.Fatalf("exit = %d, want %d", rep.Summary.ExitCode, tc.exit)
			}
			if rep.Summary.Worst != tc.worst {
				t.Fatalf("worst = %q, want %q", rep.Summary.Worst, tc.worst)
			}
			if tc.counts != nil && !tc.counts(rep.Summary) {
				t.Fatalf("counts wrong: %+v", rep.Summary)
			}
			if rep.Summary.FailOn != string(tc.failOn) {
				t.Fatalf("failOn = %q", rep.Summary.FailOn)
			}
		})
	}
}

func TestBuildStrictMediumGateFailsMedium(t *testing.T) {
	t.Parallel()
	rep := build(t, fixtureResult(finding.Finding{
		Rule: "R", Severity: finding.SeverityMedium, Title: "t", Remediation: "fix",
	}), finding.SeverityMedium)
	if rep.Summary.ExitCode != ExitFindings {
		t.Fatalf("medium must fail a medium gate: %+v", rep.Summary)
	}
}

func TestBuildInvalidFailOn(t *testing.T) {
	t.Parallel()
	if _, err := Build(fixtureResult(), BuildOptions{Now: fixedTime, FailOn: finding.Severity("bogus")}); err == nil {
		t.Fatal("expected error for invalid fail-on")
	}
}

func TestBuildDefaults(t *testing.T) {
	t.Parallel()
	rep, err := Build(fixtureResult(), BuildOptions{Now: fixedTime})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if rep.Tool.Version != "dev" || rep.Tool.Homepage != DefaultHomepage || rep.Summary.FailOn != "high" {
		t.Fatalf("defaults wrong: %+v", rep)
	}
	if rep.SchemaVersion != SchemaVersion {
		t.Fatalf("schema = %q", rep.SchemaVersion)
	}
	if !rep.Analysis.GeneratedAt.Equal(fixedTime) {
		t.Fatalf("generated_at = %v", rep.Analysis.GeneratedAt)
	}
}

func TestRepoURL(t *testing.T) {
	t.Parallel()
	rep := build(t, fixtureResult(), finding.SeverityHigh)
	if rep.Repo.URL != "https://huggingface.co/fixture/benign" {
		t.Fatalf("url = %q", rep.Repo.URL)
	}
	dataset := fixtureResult()
	dataset.RepoType = "dataset"
	rep = build(t, dataset, finding.SeverityHigh)
	if rep.Repo.URL != "https://huggingface.co/datasets/fixture/benign" {
		t.Fatalf("dataset url = %q", rep.Repo.URL)
	}
}

func TestJSONRoundTrip(t *testing.T) {
	rep := build(t, fixtureResult(finding.Finding{
		Rule: "MG-CMD-001", Severity: finding.SeverityCritical, Title: "Shell",
		Message: "m", File: "x.py", Line: 3, Remediation: "fix",
	}), finding.SeverityHigh)
	data, err := rep.JSON()
	if err != nil {
		t.Fatalf("json: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("report JSON invalid: %v", err)
	}
	if decoded["schema_version"] != SchemaVersion {
		t.Fatalf("schema_version = %v", decoded["schema_version"])
	}
	summary := decoded["summary"].(map[string]any)
	if summary["exit_code"].(float64) != ExitFindings {
		t.Fatalf("summary = %v", summary)
	}
	if !bytes.HasSuffix(data, []byte("\n")) {
		t.Fatal("JSON output must end with newline")
	}
}

func TestTextReport(t *testing.T) {
	t.Parallel()
	res := fixtureResult(finding.Finding{
		Rule: "MG-CMD-001", Severity: finding.SeverityCritical, Title: "Shell command execution",
		Message: "1 occurrence(s) in this file.", File: "x.py", Line: 3,
		Evidence: "os.system('id')", Remediation: "Remove it.", References: []string{"https://cwe.mitre.org/data/definitions/78.html"},
	})
	rep := build(t, res, finding.SeverityHigh)
	var buf bytes.Buffer
	if err := rep.Text(&buf); err != nil {
		t.Fatalf("text: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"static supply-chain check",
		"fixture/benign",
		fixtureSHA,
		"[CRITICAL] MG-CMD-001 x.py:3",
		"os.system('id')",
		"WARNING:",
		"→ exit 1",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("text report missing %q:\n%s", want, out)
		}
	}
}

func TestTextReportNoFindings(t *testing.T) {
	t.Parallel()
	rep := build(t, fixtureResult(), finding.SeverityHigh)
	var buf bytes.Buffer
	if err := rep.Text(&buf); err != nil {
		t.Fatalf("text: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "No findings") {
		t.Fatalf("missing clean-line:\n%s", out)
	}
	if strings.Contains(out, "WARNING") {
		t.Fatalf("clean run must not warn:\n%s", out)
	}
}

func TestTextReportWithDelta(t *testing.T) {
	t.Parallel()
	res := fixtureResult()
	res.Delta = &pin.Delta{
		Pinned: fixtureSHA, Current: "bbb01abcdef01abcdef01abcdef01abcdef0",
		Changes: []pin.FileChange{{Path: "a.py", Change: "modified"}},
	}
	rep := build(t, res, finding.SeverityHigh)
	var buf bytes.Buffer
	if err := rep.Text(&buf); err != nil {
		t.Fatalf("text: %v", err)
	}
	if !strings.Contains(buf.String(), "Delta   :") || !strings.Contains(buf.String(), "1 changed file(s)") {
		t.Fatalf("delta section missing:\n%s", buf.String())
	}
}
