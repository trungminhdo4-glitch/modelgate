// Package report assembles scan results into the supported output formats:
// human-readable text, JSON, Sigma and SARIF 2.1.0.
package report

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/trungminhdo4-glitch/modelgate/internal/finding"
	"github.com/trungminhdo4-glitch/modelgate/internal/pin"
	"github.com/trungminhdo4-glitch/modelgate/internal/scan"
)

// SchemaVersion of the JSON report format.
const SchemaVersion = "1.0"

// DefaultHomepage is used in every export that references the project.
const DefaultHomepage = "https://github.com/trungminhdo4-glitch/modelgate"

// Exit codes documented in the README.
const (
	ExitOK       = 0 // no finding reached fail-on
	ExitFindings = 1 // at least one finding reached fail-on
)

// ToolInfo identifies the producing tool.
type ToolInfo struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	Homepage string `json:"homepage"`
	License  string `json:"license"`
	Mode     string `json:"mode"`
}

// RepoInfo identifies the checked repository.
type RepoInfo struct {
	ID             string `json:"id"`
	Type           string `json:"type"`
	URL            string `json:"url"`
	Revision       string `json:"revision"`
	PinnedRevision string `json:"pinned_revision,omitempty"`
}

// AnalysisInfo records how and when the check ran.
type AnalysisInfo struct {
	GeneratedAt    time.Time `json:"generated_at"`
	AnalyzedFiles  []string  `json:"analyzed_files"`
	AutoMapTargets []string  `json:"auto_map_targets,omitempty"`
}

// Summary aggregates severities and the resulting exit code.
type Summary struct {
	Info     int    `json:"info"`
	Low      int    `json:"low"`
	Medium   int    `json:"medium"`
	High     int    `json:"high"`
	Critical int    `json:"critical"`
	Worst    string `json:"worst"`
	FailOn   string `json:"fail_on"`
	ExitCode int    `json:"exit_code"`
}

// Report is the canonical JSON document produced by `modelgate check`.
type Report struct {
	SchemaVersion string               `json:"schema_version"`
	Tool          ToolInfo             `json:"tool"`
	Repo          RepoInfo             `json:"repo"`
	Analysis      AnalysisInfo         `json:"analysis"`
	Trust         scan.TrustAssessment `json:"trust_remote_code"`
	Findings      []finding.Finding    `json:"findings"`
	Summary       Summary              `json:"summary"`
	Delta         *pin.Delta           `json:"delta,omitempty"`
}

// BuildOptions controls version stamping, clock injection and fail-on level.
type BuildOptions struct {
	ToolVersion string
	Homepage    string
	Now         time.Time
	FailOn      finding.Severity
}

// Build converts a scan result into a report. The report is deterministic for
// a fixed clock value, which keeps golden tests and reproducible builds honest.
func Build(res *scan.Result, opts BuildOptions) (*Report, error) {
	if opts.FailOn == "" {
		opts.FailOn = finding.SeverityHigh
	}
	if _, err := opts.FailOn.Rank(); err != nil {
		return nil, err
	}
	if opts.Homepage == "" {
		opts.Homepage = DefaultHomepage
	}
	if opts.ToolVersion == "" {
		opts.ToolVersion = "dev"
	}

	r := &Report{
		SchemaVersion: SchemaVersion,
		Tool: ToolInfo{
			Name:     "modelgate",
			Version:  opts.ToolVersion,
			Homepage: opts.Homepage,
			License:  "Apache-2.0",
			Mode:     "static-read-only",
		},
		Repo: RepoInfo{
			ID:             res.RepoID,
			Type:           res.RepoType,
			URL:            repoURL(res.RepoType, res.RepoID),
			Revision:       res.Revision,
			PinnedRevision: res.PinnedRevision,
		},
		Analysis: AnalysisInfo{
			GeneratedAt:    opts.Now.UTC(),
			AnalyzedFiles:  append([]string(nil), res.AnalyzedFiles...),
			AutoMapTargets: append([]string(nil), res.AutoMapTargets...),
		},
		Trust:    res.Trust,
		Findings: append([]finding.Finding(nil), res.Findings...),
		Delta:    res.Delta,
	}

	summary := Summary{FailOn: string(opts.FailOn)}
	for _, f := range r.Findings {
		switch f.Severity {
		case finding.SeverityInfo:
			summary.Info++
		case finding.SeverityLow:
			summary.Low++
		case finding.SeverityMedium:
			summary.Medium++
		case finding.SeverityHigh:
			summary.High++
		case finding.SeverityCritical:
			summary.Critical++
		}
	}
	summary.Worst = "none"
	for _, s := range []struct {
		sev   finding.Severity
		count int
	}{{finding.SeverityCritical, summary.Critical}, {finding.SeverityHigh, summary.High},
		{finding.SeverityMedium, summary.Medium}, {finding.SeverityLow, summary.Low},
		{finding.SeverityInfo, summary.Info}} {
		if s.count > 0 {
			summary.Worst = string(s.sev)
			break
		}
	}
	summary.ExitCode = ExitOK
	for _, f := range r.Findings {
		ok, err := f.Severity.AtLeast(opts.FailOn)
		if err != nil {
			return nil, err
		}
		if ok {
			summary.ExitCode = ExitFindings
			break
		}
	}
	r.Summary = summary
	return r, nil
}

// repoURL renders the canonical web URL of a repository.
func repoURL(repoType, id string) string {
	if repoType == "dataset" {
		return "https://huggingface.co/datasets/" + id
	}
	return "https://huggingface.co/" + id
}

// JSON renders the report as indented UTF-8 JSON with a trailing newline.
func (r *Report) JSON() ([]byte, error) {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("report: encoding json: %w", err)
	}
	return append(data, '\n'), nil
}
