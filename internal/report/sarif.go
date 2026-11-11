package report

import (
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/trungminhdo4-glitch/modelgate/internal/finding"
)

// SARIF renders the report as SARIF 2.1.0, the CI-native format understood
// by GitHub code scanning and most CI annotation systems.
func (r *Report) SARIF() ([]byte, error) {
	rules := collectRules(r.Findings)
	results := make([]sarifResult, 0, len(r.Findings))
	for _, f := range r.Findings {
		res := sarifResult{
			RuleID: f.Rule,
			Level:  sarifLevel(f.Severity),
			Message: sarifText{
				Text: fmt.Sprintf("%s: %s (%s)", f.Title, f.Message, strings.ToUpper(string(f.Severity))),
			},
			PartialFingerprints: map[string]string{"modelgate/v1": fingerprint(f)},
		}
		if f.File != "" {
			loc := sarifLocation{PhysicalLocation: sarifPhysical{
				ArtifactLocation: sarifArtifact{URI: f.File},
			}}
			if f.Line > 0 {
				loc.PhysicalLocation.Region = &sarifRegion{StartLine: f.Line}
			}
			res.Locations = []sarifLocation{loc}
		}
		results = append(results, res)
	}

	log := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "modelgate",
				InformationURI: r.Tool.Homepage,
				Version:        r.Tool.Version,
				Rules:          rules,
			}},
			Results: results,
			Invocations: []sarifInvocation{{
				ExecutionSuccessful: true,
				Properties: sarifProperties{
					"repository": r.Repo.URL,
					"revision":   r.Repo.Revision,
					"failOn":     r.Summary.FailOn,
					"mode":       r.Tool.Mode,
					"exitCode":   fmt.Sprintf("%d", r.Summary.ExitCode),
				},
			}},
		}},
	}
	data, err := json.MarshalIndent(log, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("report: encoding sarif: %w", err)
	}
	return append(data, '\n'), nil
}

// collectRules builds the deduplicated, sorted SARIF rule catalogue.
func collectRules(fs []finding.Finding) []sarifRule {
	byID := map[string]finding.Finding{}
	var ids []string
	for _, f := range fs {
		if _, ok := byID[f.Rule]; !ok {
			byID[f.Rule] = f
			ids = append(ids, f.Rule)
		}
	}
	sort.Strings(ids)
	out := make([]sarifRule, 0, len(ids))
	for _, id := range ids {
		f := byID[id]
		rule := sarifRule{
			ID:               id,
			Name:             sanitizeRuleName(f.Title),
			ShortDescription: sarifText{Text: f.Title},
		}
		if f.Remediation != "" {
			rule.Help = &sarifText{Text: f.Remediation}
		}
		if len(f.References) > 0 {
			rule.HelpURI = f.References[0]
		}
		out = append(out, rule)
	}
	return out
}

func sanitizeRuleName(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	return b.String()
}

func sarifLevel(s finding.Severity) string {
	switch s {
	case finding.SeverityCritical, finding.SeverityHigh:
		return "error"
	case finding.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

func fingerprint(f finding.Finding) string {
	sum := sha1.Sum([]byte(f.Rule + "\x00" + f.File + "\x00" + f.Evidence))
	return fmt.Sprintf("%x", sum[:8])
}

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool        sarifTool         `json:"tool"`
	Results     []sarifResult     `json:"results"`
	Invocations []sarifInvocation `json:"invocations,omitempty"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Version        string      `json:"version"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string     `json:"id"`
	Name             string     `json:"name"`
	ShortDescription sarifText  `json:"shortDescription"`
	Help             *sarifText `json:"help,omitempty"`
	HelpURI          string     `json:"helpUri,omitempty"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	Level               string            `json:"level"`
	Message             sarifText         `json:"message"`
	Locations           []sarifLocation   `json:"locations,omitempty"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           *sarifRegion  `json:"region,omitempty"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

type sarifInvocation struct {
	ExecutionSuccessful bool            `json:"executionSuccessful"`
	Properties          sarifProperties `json:"properties,omitempty"`
}

type sarifProperties map[string]any
