// Package finding defines the shared finding model used by every ModelGate
// analysis stage and every export format (text, JSON, Sigma, SARIF, CycloneDX).
package finding

import (
	"fmt"
	"sort"
	"strings"
)

// Severity is the ordered severity of a finding. The zero value is SeverityInfo.
type Severity string

// Severity levels ordered from least to most severe.
const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

var severityRank = map[Severity]int{
	SeverityInfo:     0,
	SeverityLow:      1,
	SeverityMedium:   2,
	SeverityHigh:     3,
	SeverityCritical: 4,
}

// Severities returns all severities in ascending order.
func Severities() []Severity {
	return []Severity{SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical}
}

// ParseSeverity validates a severity string from configuration or CLI input.
func ParseSeverity(v string) (Severity, error) {
	s := Severity(strings.ToLower(strings.TrimSpace(v)))
	if _, ok := severityRank[s]; !ok {
		return "", fmt.Errorf("unknown severity %q (want info|low|medium|high|critical)", v)
	}
	return s, nil
}

// Rank returns the numeric rank of the severity. It errors for unknown values
// so that a typo can never silently pass a fail-on comparison.
func (s Severity) Rank() (int, error) {
	r, ok := severityRank[s]
	if !ok {
		return 0, fmt.Errorf("unknown severity %q", string(s))
	}
	return r, nil
}

// AtLeast reports whether s is at least as severe as min. Unknown values
// return false and an error; callers must not treat an error as a match.
func (s Severity) AtLeast(min Severity) (bool, error) {
	a, err := s.Rank()
	if err != nil {
		return false, err
	}
	b, err := min.Rank()
	if err != nil {
		return false, err
	}
	return a >= b, nil
}

// Finding is a single detection result.
type Finding struct {
	// Rule is the stable rule identifier, e.g. "MG-CMD-001".
	Rule string `json:"rule"`
	// Severity of this finding.
	Severity Severity `json:"severity"`
	// Title is a short human-readable rule name.
	Title string `json:"title"`
	// Message describes what was observed in this concrete case.
	Message string `json:"message"`
	// File is the repository-relative path the finding refers to.
	File string `json:"file,omitempty"`
	// Line is the 1-based line number inside File (0 if not applicable).
	Line int `json:"line,omitempty"`
	// Evidence is a length-capped excerpt of the offending source line.
	Evidence string `json:"evidence,omitempty"`
	// Remediation tells the reader how to remove or review the risk.
	Remediation string `json:"remediation"`
	// References are URLs or rule identifiers for further reading.
	References []string `json:"references,omitempty"`
}

// Key returns a stable identity for delta comparisons between two revisions.
func (f Finding) Key() string {
	return strings.Join([]string{f.Rule, f.File, f.Evidence}, "\x00")
}

// SortFindings orders findings deterministically: severity descending, then
// rule, file, and line. Reports stay byte-stable for reproducible builds.
func SortFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		if fs[i].Severity != fs[j].Severity {
			ri, _ := fs[i].Severity.Rank()
			rj, _ := fs[j].Severity.Rank()
			return ri > rj
		}
		if fs[i].Rule != fs[j].Rule {
			return fs[i].Rule < fs[j].Rule
		}
		if fs[i].File != fs[j].File {
			return fs[i].File < fs[j].File
		}
		return fs[i].Line < fs[j].Line
	})
}
