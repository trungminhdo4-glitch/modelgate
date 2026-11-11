package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/trung-dev/modelgate/internal/finding"
)

// Text renders the human-readable report. Findings are grouped by severity,
// and a clear warning line is printed whenever the run will fail a gate.
func (r *Report) Text(w io.Writer) error {
	var b strings.Builder
	fmt.Fprintf(&b, "ModelGate %s — static supply-chain check (read-only, non-executing)\n", r.Tool.Version)
	fmt.Fprintf(&b, "Repository : %s (%s)\n", r.Repo.ID, r.Repo.Type)
	fmt.Fprintf(&b, "URL        : %s\n", r.Repo.URL)
	fmt.Fprintf(&b, "Revision   : %s\n", r.Repo.Revision)
	if r.Repo.PinnedRevision != "" {
		fmt.Fprintf(&b, "Pinned     : %s\n", r.Repo.PinnedRevision)
	}
	fmt.Fprintf(&b, "Analyzed   : %d python file(s)", len(r.Analysis.AnalyzedFiles))
	if len(r.Analysis.AnalyzedFiles) > 0 {
		fmt.Fprintf(&b, ": %s", strings.Join(r.Analysis.AnalyzedFiles, ", "))
	}
	b.WriteString("\n")
	fmt.Fprintf(&b, "trust_remote_code: config=%t auto_map=%d card_mentions=%d\n",
		r.Trust.ConfigFlag, r.Trust.AutoMapCount, r.Trust.CardMentions)

	if len(r.Findings) == 0 {
		b.WriteString("\nNo findings. The check found no known risky patterns.\n")
	} else {
		b.WriteString("\n")
		for _, f := range r.Findings {
			writeFinding(&b, f)
		}
	}

	s := r.Summary
	fmt.Fprintf(&b, "\nSummary: %d critical, %d high, %d medium, %d low, %d info — worst=%s, fail-on=%s → exit %d\n",
		s.Critical, s.High, s.Medium, s.Low, s.Info, s.Worst, s.FailOn, s.ExitCode)
	if s.ExitCode == ExitFindings {
		fmt.Fprintf(&b, "WARNING: %d finding(s) at or above fail-on=%s — do not load this revision without review.\n",
			countAtLeast(r, finding.Severity(s.FailOn)), s.FailOn)
	}
	if r.Delta != nil {
		fmt.Fprintf(&b, "Delta   : pinned %s vs current %s — %d changed file(s), %d new finding(s), %d resolved finding(s).\n",
			short(r.Delta.Pinned), short(r.Delta.Current),
			len(r.Delta.Changes), len(r.Delta.NewFindings), len(r.Delta.ResolvedFindings))
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func writeFinding(b *strings.Builder, f finding.Finding) {
	loc := ""
	if f.File != "" {
		if f.Line > 0 {
			loc = fmt.Sprintf(" %s:%d", f.File, f.Line)
		} else {
			loc = " " + f.File
		}
	}
	fmt.Fprintf(b, "[%s] %s%s\n", strings.ToUpper(string(f.Severity)), f.Rule, loc)
	fmt.Fprintf(b, "  %s — %s\n", f.Title, f.Message)
	if f.Evidence != "" {
		fmt.Fprintf(b, "  evidence: %s\n", f.Evidence)
	}
	fmt.Fprintf(b, "  fix: %s\n", f.Remediation)
	if len(f.References) > 0 {
		fmt.Fprintf(b, "  refs: %s\n", strings.Join(f.References, ", "))
	}
	b.WriteString("\n")
}

func countAtLeast(r *Report, min finding.Severity) int {
	n := 0
	for _, f := range r.Findings {
		if ok, err := f.Severity.AtLeast(min); err == nil && ok {
			n++
		}
	}
	return n
}

func short(sha string) string {
	if len(sha) > 12 {
		return sha[:12]
	}
	return sha
}
