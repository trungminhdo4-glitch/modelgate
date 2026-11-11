package report

import (
	"encoding/json"
	"testing"

	"github.com/trungminhdo4-glitch/modelgate/internal/finding"
)

func TestSARIFOutput(t *testing.T) {
	t.Parallel()
	rep := build(t, fixtureResult(
		finding.Finding{
			Rule: "MG-CMD-001", Severity: finding.SeverityCritical, Title: "Shell command execution via the os module",
			Message: "observed", File: "x.py", Line: 3, Evidence: "os.system('id')",
			Remediation: "Remove it.", References: []string{"https://cwe.mitre.org/data/definitions/78.html"},
		},
		finding.Finding{
			Rule: "MG-TRUST-001", Severity: finding.SeverityMedium, Title: "trust_remote_code",
			Message: "flag set", File: "config.json", Remediation: "Review.",
		},
		finding.Finding{
			Rule: "MG-TRUST-001", Severity: finding.SeverityMedium, Title: "trust_remote_code",
			Message: "flag set again", File: "config.json", Remediation: "Review.",
		},
	), finding.SeverityHigh)

	data, err := rep.SARIF()
	if err != nil {
		t.Fatalf("sarif: %v", err)
	}
	var log sarifLog
	if err := json.Unmarshal(data, &log); err != nil {
		t.Fatalf("sarif JSON invalid: %v", err)
	}
	if log.Version != "2.1.0" || log.Schema == "" {
		t.Fatalf("sarif header = %+v", log)
	}
	if len(log.Runs) != 1 {
		t.Fatalf("runs = %d", len(log.Runs))
	}
	run := log.Runs[0]
	if run.Tool.Driver.Name != "modelgate" || run.Tool.Driver.Version != "1.0.0" {
		t.Fatalf("driver = %+v", run.Tool.Driver)
	}
	// Rules are deduplicated by ID: two MG-TRUST-001 findings share one rule.
	if len(run.Tool.Driver.Rules) != 2 {
		t.Fatalf("rules = %+v", run.Tool.Driver.Rules)
	}
	if len(run.Results) != 3 {
		t.Fatalf("results = %d", len(run.Results))
	}
	if run.Results[0].Level != "error" || run.Results[2].Level != "warning" {
		t.Fatalf("levels = %+v", run.Results)
	}
	if run.Results[0].Locations[0].PhysicalLocation.Region.StartLine != 3 {
		t.Fatalf("region = %+v", run.Results[0].Locations)
	}
	if run.Results[0].PartialFingerprints["modelgate/v1"] == "" {
		t.Fatal("missing fingerprint")
	}
	if run.Invocations[0].ExecutionSuccessful != true {
		t.Fatal("invocation must record success")
	}
}

func TestSARIFLevelMapping(t *testing.T) {
	t.Parallel()
	cases := map[finding.Severity]string{
		finding.SeverityCritical: "error",
		finding.SeverityHigh:     "error",
		finding.SeverityMedium:   "warning",
		finding.SeverityLow:      "note",
		finding.SeverityInfo:     "note",
	}
	for sev, want := range cases {
		if got := sarifLevel(sev); got != want {
			t.Fatalf("level(%q) = %q, want %q", sev, got, want)
		}
	}
}

func TestSARIFDeterministic(t *testing.T) {
	t.Parallel()
	rep := build(t, fixtureResult(finding.Finding{
		Rule: "R", Severity: finding.SeverityHigh, Title: "T", Message: "m", Remediation: "fix",
	}), finding.SeverityHigh)
	a, err := rep.SARIF()
	if err != nil {
		t.Fatal(err)
	}
	b, err := rep.SARIF()
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Fatal("sarif must be byte-stable")
	}
}

func TestSanitizeRuleName(t *testing.T) {
	t.Parallel()
	if got := sanitizeRuleName("Shell command (os)"); got != "Shell_command__os_" {
		t.Fatalf("got %q", got)
	}
}
